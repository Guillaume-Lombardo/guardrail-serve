package eval_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

func reportJSON(t *testing.T, report *eval.Report) (map[string]any, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	return decoded, buf.String()
}

func at(t *testing.T, doc map[string]any, path ...string) any {
	t.Helper()
	var current any = doc
	for _, key := range path {
		if list, isList := current.([]any); isList {
			index, err := strconv.Atoi(key)
			if err != nil || index < 0 || index >= len(list) {
				t.Fatalf("%v: bad index %q", path, key)
			}
			current = list[index]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("%v: %v is not an object", path, current)
		}
		if current, ok = object[key]; !ok {
			t.Fatalf("%v: missing %q", path, key)
		}
	}
	return current
}

func sampleReport(t *testing.T) *eval.Report {
	t.Helper()
	return sampleReportOn(t, newFakeService(t))
}

func sampleReportOn(t *testing.T, svc *fakeService) *eval.Report {
	t.Helper()
	svc.Findings = map[string][]string{"hit": {"detect_pii"}, "fp": {"detect_pii"}}
	corpus := loadCorpusFile(t, corpusFile(t, "unit",
		caseLine("c-1", "en", "hit", `"detect_pii":true,"detect_secret":false`),
		caseLine("c-2", "fr", "fp", `"detect_pii":false,"detect_secret":false`, `"tags":["hard"]`),
		caseLine("c-3", "fr", "nothing", `"detect_pii":false,"detect_secret":false`),
	))
	_, report := runAnnotate(t, svc, corpus)
	return report
}

func TestReportJSONContract(t *testing.T) {
	report := sampleReport(t)
	doc, text := reportJSON(t, report)

	if strings.Contains(text, "NaN") || strings.Contains(text, "Inf") {
		t.Fatalf("report contains a non-finite number:\n%s", text)
	}
	if !strings.HasSuffix(text, "}\n") {
		t.Fatal("report must end with a newline")
	}
	if at(t, doc, "report_version") != float64(1) || at(t, doc, "status") != "complete" {
		t.Fatalf("header = %v %v", at(t, doc, "report_version"), at(t, doc, "status"))
	}
	for path, want := range map[string]any{
		"target/mode": "annotate", "target/policy": "audit",
		"run/cases": float64(3), "run/requests": float64(3), "run/cases_errored": float64(0),
		"corpora/0/detectors/detect_pii/counts/tp": float64(1), "corpora/0/detectors/detect_pii/counts/fp": float64(1), "corpora/0/detectors/detect_pii/counts/tn": float64(1),
		"corpora/0/detectors/detect_pii/metrics/precision/value":   0.5,
		"corpora/0/detectors/detect_pii/metrics/precision/defined": true,
		"corpora/0/detectors/detect_pii/metrics/recall/value":      float64(1),
		"corpora/0/detectors/detect_pii/metrics/fpr/value":         0.5,
		// detect_secret has no positive: recall undefined, reported as 0 with defined=false.
		"corpora/0/detectors/detect_secret/counts/tn":                 float64(3),
		"corpora/0/detectors/detect_secret/metrics/recall/value":      float64(0),
		"corpora/0/detectors/detect_secret/metrics/recall/defined":    false,
		"corpora/0/detectors/detect_secret/metrics/precision/defined": false,
		"corpora/0/detectors/detect_secret/metrics/fpr/value":         float64(0),
		"corpora/0/detectors/detect_secret/metrics/fpr/defined":       true,
		"corpora/0/detectors/detect_pii/by_language/fr/counts/fp":     float64(1),
		"corpora/0/detectors/detect_pii/by_tag/hard/counts/fp":        float64(1),
		"corpora/0/aggregate/micro/counts/tp":                         float64(1),
		"corpora/0/aggregate/micro/counts/tn":                         float64(4),
		"corpora/0/aggregate/micro/metrics/precision/value":           0.5,
		"errors/total": float64(0),
	} {
		if got := at(t, doc, strings.Split(path, "/")...); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	corpora := at(t, doc, "corpora").([]any)
	first := corpora[0].(map[string]any)
	if first["name"] != "unit" || first["cases"] != float64(3) || len(first["sha256"].(string)) != 64 {
		t.Errorf("corpora = %v", corpora)
	}
	for _, empty := range []string{"warnings", "errors/samples"} {
		if v := at(t, doc, strings.Split(empty, "/")...); v == nil {
			t.Errorf("%s must be an empty array, not null", empty)
		}
	}
	for _, key := range []string{"started_at", "finished_at", "duration", "duration_ms", "timestamp"} {
		if strings.Contains(text, `"`+key+`"`) {
			t.Errorf("report must be free of %s to stay stable", key)
		}
	}
}

func TestReportIsDeterministic(t *testing.T) {
	svc := newFakeService(t)
	_, first := reportJSON(t, sampleReportOn(t, svc))
	_, second := reportJSON(t, sampleReportOn(t, svc))
	if first != second {
		t.Fatalf("reports differ:\n%s\n%s", first, second)
	}
}

func TestReportTextIsReadable(t *testing.T) {
	var buf bytes.Buffer
	if err := sampleReport(t).WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"status:  complete", "mode=annotate policy=audit", "corpus:  unit (3 cases",
		"detector", "precision", "n/a", // detect_secret precision and recall are undefined
		"detect_pii", "0.500", "micro", "macro",
		"By language", "detect_pii/fr", "breakdowns are in the JSON report",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "NaN") {
		t.Error("text report contains NaN")
	}
}

func TestReportErrorSamplesAreBounded(t *testing.T) {
	svc := newFakeService(t)
	svc.Override = func(w http.ResponseWriter, _ *http.Request, _ received) bool {
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	}
	lines := []string{}
	for i := 0; i < 25; i++ {
		lines = append(lines, caseLine(fmt.Sprintf("c-%02d", i), "en", fmt.Sprintf("t%d", i), `"detect_pii":true`))
	}
	corpus := loadCorpusFile(t, corpusFile(t, "unit", lines...))
	client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
	result, err := eval.Run(context.Background(), client, eval.RunConfig{Mode: eval.ModeAnnotate, Policy: "audit"}, []*eval.Corpus{corpus})
	if err != nil {
		t.Fatal(err)
	}
	report := eval.BuildReport(result, eval.Target{BaseURL: client.BaseURL(), Mode: eval.ModeAnnotate, Policy: "audit"}, []*eval.Corpus{corpus})
	if report.Errors.Total != 25 || len(report.Errors.Samples) != 20 || !report.Errors.Truncated || report.Errors.ByKind["http_status"] != 25 {
		t.Fatalf("errors = %+v", report.Errors)
	}
	var buf bytes.Buffer
	if err := report.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "5 more not listed") || !strings.Contains(buf.String(), "http_status: 25") || !strings.Contains(buf.String(), "HTTP 503 Service Unavailable") {
		t.Fatalf("text:\n%s", buf.String())
	}
	if got := report.Corpora[0].Detectors["detect_pii"]; got.Counts.Total() != 0 || got.Errored != 25 {
		t.Fatalf("detector = %+v", got)
	}
}
