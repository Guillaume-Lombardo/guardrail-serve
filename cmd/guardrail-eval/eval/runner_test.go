package eval_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

func loadCorpusFile(t *testing.T, path string) *eval.Corpus {
	t.Helper()
	corpus, err := eval.LoadCorpus(path)
	if err != nil {
		t.Fatal(err)
	}
	return corpus
}

func runAnnotate(t *testing.T, svc *fakeService, corpora ...*eval.Corpus) (*eval.Result, *eval.Report) {
	t.Helper()
	client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
	cfg := eval.RunConfig{Mode: eval.ModeAnnotate, Policy: "audit"}
	result, err := eval.Run(context.Background(), client, cfg, corpora)
	if err != nil {
		t.Fatal(err)
	}
	return result, eval.BuildReport(result, eval.Target{BaseURL: client.BaseURL(), Mode: cfg.Mode, Policy: cfg.Policy}, corpora)
}

func TestRunAnnotateCountsEveryLabelledDetector(t *testing.T) {
	svc := newFakeService(t)
	svc.Findings = map[string][]string{
		"mail zoe": {"detect_pii"},
		"fp":       {"detect_pii", "detect_secret"}, // detect_secret is not labelled on this case: ignored
	}
	corpus := loadCorpusFile(t, corpusFile(t, "unit",
		caseLine("c-1", "en", "mail zoe", `"detect_pii":true,"detect_secret":false`),
		caseLine("c-2", "en", "plain", `"detect_pii":false,"detect_secret":false`),
		caseLine("c-3", "fr", "fp", `"detect_pii":false`, `"tags":["hard"]`),
		caseLine("c-4", "fr", "miss", `"detect_pii":false,"detect_secret":true`, `"tags":["hard"]`),
	))
	result, report := runAnnotate(t, svc, corpus)

	if result.Status != eval.StatusComplete || result.Cases != 4 || result.Requests != 4 || len(svc.Seen()) != 4 {
		t.Fatalf("result = %+v requests = %d", result, len(svc.Seen()))
	}
	want := map[string]eval.Confusion{
		"detect_pii":    {TP: 1, FP: 1, TN: 2},
		"detect_secret": {TN: 2, FN: 1},
	}
	for name, counts := range want {
		if got := report.Corpora[0].Detectors[name].Counts; got != counts {
			t.Errorf("%s = %+v, want %+v", name, got, counts)
		}
	}
	pii := report.Corpora[0].Detectors["detect_pii"]
	if pii.ByLanguage["fr"].Counts != (eval.Confusion{FP: 1, TN: 1}) || pii.ByLanguage["en"].Counts != (eval.Confusion{TP: 1, TN: 1}) {
		t.Errorf("by language = %+v", pii.ByLanguage)
	}
	if pii.ByTag["hard"].Counts != (eval.Confusion{FP: 1, TN: 1}) {
		t.Errorf("by tag = %+v", pii.ByTag)
	}
	if got := report.Corpora[0].Aggregate.Micro.Counts; got != (eval.Confusion{TP: 1, FP: 1, TN: 4, FN: 1}) {
		t.Errorf("micro = %+v", got)
	}
}

func TestMacroAveragesDefinedMetricsOnly(t *testing.T) {
	svc := newFakeService(t)
	svc.Findings = map[string][]string{"hit": {"detect_pii"}, "false alarm": {"detect_pii"}}
	corpus := loadCorpusFile(t, corpusFile(t, "unit",
		caseLine("c-1", "en", "hit", `"detect_pii":true`),
		caseLine("c-2", "en", "false alarm", `"detect_pii":false`),
		caseLine("c-3", "en", "nothing", `"detect_secret":false`), // detect_secret has no positives: recall undefined
	))
	_, report := runAnnotate(t, svc, corpus)
	macro := report.Corpora[0].Aggregate.Macro
	// precision: pii 0.5 defined, secret undefined -> mean over one detector.
	if !macro.Precision.Defined || macro.Precision.Value != 0.5 {
		t.Errorf("precision = %+v", macro.Precision)
	}
	// recall: only pii defined (1.0).
	if !macro.Recall.Defined || macro.Recall.Value != 1 {
		t.Errorf("recall = %+v", macro.Recall)
	}
	// fpr: pii 1.0, secret 0 (one negative, no false alarm) -> 0.5.
	if !macro.FPR.Defined || macro.FPR.Value != 0.5 {
		t.Errorf("fpr = %+v", macro.FPR)
	}
}

func TestRunAnnotateWarnsWhenADetectorNeverReports(t *testing.T) {
	svc := newFakeService(t)
	corpus := loadCorpusFile(t, corpusFile(t, "unit", caseLine("c-1", "en", "x", `"prompt_injection":true`)))
	_, report := runAnnotate(t, svc, corpus)
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], `"prompt_injection"`) || !strings.Contains(report.Warnings[0], `"audit"`) {
		t.Fatalf("warnings = %v", report.Warnings)
	}
}

func TestRunEnforceUsesOneScanRequestPerLabelledDetector(t *testing.T) {
	svc := newFakeService(t)
	svc.Scans = map[string]string{
		"/scan/pii|both":             "GUARDRAIL_INTERVENED",
		"/scan/secrets|both":         "BLOCKED",
		"/scan/prompt-injection|bad": "BLOCKED",
	}
	corpus := loadCorpusFile(t, corpusFile(t, "unit",
		caseLine("c-1", "en", "both", `"detect_pii":true,"detect_secret":true`),
		caseLine("c-2", "en", "bad", `"prompt_injection":true`, `"input_type":"response"`),
		caseLine("c-3", "en", "clean", `"prompt_injection":false,"detect_pii":false`),
	))
	client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
	cfg := eval.RunConfig{Mode: eval.ModeEnforce}
	result, err := eval.Run(context.Background(), client, cfg, []*eval.Corpus{corpus})
	if err != nil {
		t.Fatal(err)
	}
	report := eval.BuildReport(result, eval.Target{BaseURL: client.BaseURL(), Mode: cfg.Mode}, []*eval.Corpus{corpus})

	paths := []string{}
	for _, req := range svc.Seen() {
		paths = append(paths, req.Path+":"+req.Body.InputType)
	}
	wantPaths := "/scan/pii:request /scan/secrets:request /scan/prompt-injection:response /scan/pii:request /scan/prompt-injection:request"
	if strings.Join(paths, " ") != wantPaths || result.Requests != 5 {
		t.Fatalf("paths = %v", paths)
	}
	for name, want := range map[string]eval.Confusion{
		"detect_pii": {TP: 1, TN: 1}, "detect_secret": {TP: 1}, "prompt_injection": {TP: 1, TN: 1},
	} {
		if got := report.Corpora[0].Detectors[name].Counts; got != want {
			t.Errorf("%s = %+v, want %+v", name, got, want)
		}
	}
	if report.Target.Policy != "" {
		t.Errorf("enforce target must not name a policy: %+v", report.Target)
	}
}

func TestRunConfigValidation(t *testing.T) {
	custom := loadCorpusFile(t, corpusFile(t, "unit", caseLine("c-1", "en", "x", `"my_detector":true`)))
	ok := loadCorpusFile(t, corpusFile(t, "ok", caseLine("c-1", "en", "x", `"detect_pii":true`)))
	for name, tc := range map[string]struct {
		cfg     eval.RunConfig
		corpora []*eval.Corpus
		want    string
	}{
		"enforce without scan route": {eval.RunConfig{Mode: eval.ModeEnforce}, []*eval.Corpus{custom}, `"my_detector"`},
		"annotate custom detector":   {eval.RunConfig{Mode: eval.ModeAnnotate, Policy: "audit"}, []*eval.Corpus{custom}, ""},
		"bad policy":                 {eval.RunConfig{Mode: eval.ModeAnnotate, Policy: "../x"}, []*eval.Corpus{ok}, "policy"},
		"unknown mode":               {eval.RunConfig{Mode: "dry"}, []*eval.Corpus{ok}, "unsupported mode"},
		"negative consecutive":       {eval.RunConfig{Mode: eval.ModeEnforce, MaxConsecutiveErrors: -1}, []*eval.Corpus{ok}, "negative"},
	} {
		t.Run(name, func(t *testing.T) {
			svc := newFakeService(t)
			client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
			_, err := eval.Run(context.Background(), client, tc.cfg, tc.corpora)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if tc.want != "" && len(svc.Seen()) != 0 {
				t.Fatal("requests were sent despite an invalid configuration")
			}
		})
	}
}

func TestFailedRequestsAreExcludedFromCountsAndReported(t *testing.T) {
	svc := newFakeService(t)
	svc.Findings = map[string][]string{"hit": {"detect_pii"}}
	svc.Override = func(w http.ResponseWriter, _ *http.Request, req received) bool {
		switch req.Body.Texts[0] {
		case "broken":
			w.WriteHeader(http.StatusInternalServerError)
			return true
		case "huge":
			_, _ = w.Write([]byte(`{"decision":"BLOCKED","findings":[]}`))
			return true
		}
		return false
	}
	corpus := loadCorpusFile(t, corpusFile(t, "unit",
		caseLine("c-1", "en", "hit", `"detect_pii":true`),
		caseLine("c-2", "en", "broken", `"detect_pii":true,"detect_secret":false`),
		caseLine("c-3", "en", "huge", `"detect_pii":false`),
		caseLine("c-4", "en", "clean", `"detect_pii":false`),
	))
	result, report := runAnnotate(t, svc, corpus)

	if result.Status != eval.StatusCompleteWithErrors || result.Cases != 4 || result.CasesErrored != 2 {
		t.Fatalf("result = %+v", result)
	}
	// Neither the 500 nor the limit block is a detection outcome.
	if got := report.Corpora[0].Detectors["detect_pii"]; got.Counts != (eval.Confusion{TP: 1, TN: 1}) || got.Errored != 2 {
		t.Errorf("detect_pii = %+v", got)
	}
	if got := report.Corpora[0].Detectors["detect_secret"]; got.Counts.Total() != 0 || got.Errored != 1 {
		t.Errorf("detect_secret = %+v", got)
	}
	if report.Errors.Total != 2 || report.Errors.ByKind["http_status"] != 1 || report.Errors.ByKind["limit_exceeded"] != 1 {
		t.Errorf("errors = %+v", report.Errors)
	}
	for _, sample := range report.Errors.Samples {
		if strings.Contains(sample.Message, "broken") || strings.Contains(sample.Message, "huge") {
			t.Errorf("sample leaks the text: %+v", sample)
		}
	}
}

func TestRunAbortsOnRejectedCredentials(t *testing.T) {
	svc := newFakeService(t)
	svc.Override = func(w http.ResponseWriter, _ *http.Request, _ received) bool {
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	corpus := loadCorpusFile(t, corpusFile(t, "unit",
		caseLine("c-1", "en", "a", `"detect_pii":true`), caseLine("c-2", "en", "b", `"detect_pii":true`)))
	result, _ := runAnnotate(t, svc, corpus)
	if result.Status != eval.StatusAborted || !strings.Contains(result.AbortReason, "HTTP 401") || result.Requests != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunAbortsAfterConsecutiveErrorsButNotOnLimitBlocks(t *testing.T) {
	lines := []string{}
	for i := 0; i < 8; i++ {
		lines = append(lines, caseLine(fmt.Sprintf("c-%d", i), "en", fmt.Sprintf("t%d", i), `"detect_pii":true`))
	}
	corpus := loadCorpusFile(t, corpusFile(t, "unit", lines...))

	t.Run("server errors", func(t *testing.T) {
		svc := newFakeService(t)
		svc.Override = func(w http.ResponseWriter, _ *http.Request, _ received) bool {
			w.WriteHeader(http.StatusBadGateway)
			return true
		}
		client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
		result, err := eval.Run(context.Background(), client, eval.RunConfig{Mode: eval.ModeAnnotate, Policy: "audit", MaxConsecutiveErrors: 3}, []*eval.Corpus{corpus})
		if err != nil || result.Status != eval.StatusAborted || result.Requests != 3 || !strings.Contains(result.AbortReason, "3 consecutive") {
			t.Fatalf("result = %+v err = %v", result, err)
		}
	})
	t.Run("a success resets the streak", func(t *testing.T) {
		svc := newFakeService(t)
		svc.Override = func(w http.ResponseWriter, _ *http.Request, req received) bool {
			if req.Body.Texts[0] == "t2" || req.Body.Texts[0] == "t5" {
				return false
			}
			w.WriteHeader(http.StatusBadGateway)
			return true
		}
		client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
		result, err := eval.Run(context.Background(), client, eval.RunConfig{Mode: eval.ModeAnnotate, Policy: "audit", MaxConsecutiveErrors: 3}, []*eval.Corpus{corpus})
		if err != nil || result.Status != eval.StatusCompleteWithErrors || result.Requests != 8 {
			t.Fatalf("result = %+v err = %v", result, err)
		}
	})
	t.Run("limit blocks do not count", func(t *testing.T) {
		svc := newFakeService(t)
		svc.Override = func(w http.ResponseWriter, _ *http.Request, _ received) bool {
			_, _ = w.Write([]byte(`{"decision":"BLOCKED","findings":[]}`))
			return true
		}
		client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
		result, err := eval.Run(context.Background(), client, eval.RunConfig{Mode: eval.ModeAnnotate, Policy: "audit", MaxConsecutiveErrors: 2}, []*eval.Corpus{corpus})
		if err != nil || result.Status != eval.StatusCompleteWithErrors || result.Requests != 8 {
			t.Fatalf("result = %+v err = %v", result, err)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		svc := newFakeService(t)
		svc.Override = func(w http.ResponseWriter, _ *http.Request, _ received) bool {
			w.WriteHeader(http.StatusBadGateway)
			return true
		}
		client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
		result, _ := eval.Run(context.Background(), client, eval.RunConfig{Mode: eval.ModeAnnotate, Policy: "audit"}, []*eval.Corpus{corpus})
		if result.Status != eval.StatusCompleteWithErrors || result.Requests != 8 {
			t.Fatalf("result = %+v", result)
		}
	})
}

func TestRunStopsWhenCanceled(t *testing.T) {
	svc := newFakeService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Override = func(w http.ResponseWriter, _ *http.Request, req received) bool {
		if req.Body.Texts[0] == "t1" {
			cancel()
		}
		return false
	}
	corpus := loadCorpusFile(t, corpusFile(t, "unit",
		caseLine("c-0", "en", "t0", `"detect_pii":false`), caseLine("c-1", "en", "t1", `"detect_pii":false`), caseLine("c-2", "en", "t2", `"detect_pii":false`)))
	client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
	result, err := eval.Run(ctx, client, eval.RunConfig{Mode: eval.ModeAnnotate, Policy: "audit"}, []*eval.Corpus{corpus})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != eval.StatusAborted || !strings.HasPrefix(result.AbortReason, "interrupted") || len(svc.Seen()) != 2 {
		t.Fatalf("result = %+v requests = %d", result, len(svc.Seen()))
	}
	if len(result.Failures) != 0 {
		t.Fatalf("an interruption is not a request failure: %+v", result.Failures)
	}
}
