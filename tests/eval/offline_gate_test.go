package eval_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/tests/eval/gate"
)

var updateBaseline = flag.Bool("update-eval-baseline", false, "explicitly replace the offline evaluation baseline; review the diff")
var evalReportDir = flag.String("eval-report-dir", "", "write text-free gate artifacts to this directory")

// offlineCorpus is one versioned corpus with its own baseline. Corpora are
// measured and compared separately (never pooled); floors are absolute targets
// on top of the no-regression comparison.
type offlineCorpus struct {
	path, baseline, artifact string
	floors                   []gate.Floor
}

// frenchInjectionFloors is the L9 target (ADR 0018): deterministic French
// prompt-injection recall >= 0.85 and FPR <= 0.05, applied separately to the
// enriched French corpus and to the historical French cases of the original one.
var frenchInjectionFloors = []gate.Floor{{Detector: "prompt_injection", Lang: "fr", MinRecall: 0.85, MaxFPR: 0.05}}

var offlineCorpora = []offlineCorpus{
	// The original corpus keeps the artifact names current.json and gate.json.
	{path: originalCorpus, baseline: "baseline/original-v1.json", artifact: "", floors: frenchInjectionFloors},
	{path: frenchInjectionCorpus, baseline: "baseline/french-injection-v1.json", artifact: "french-injection-v1.", floors: frenchInjectionFloors},
}

func TestOfflineRegressionGate(t *testing.T) {
	// Synchronous httptest startup owns an OS-assigned loopback listener:
	// no port race, subprocess, readiness sleep, environment or model provider.
	server := startService(t, config.Config{})
	client, err := eval.NewClient(eval.ClientConfig{BaseURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, entry := range offlineCorpora {
		t.Run(filepath.Base(entry.path), func(t *testing.T) {
			runOfflineGate(t, ctx, client, server.URL, entry)
		})
	}
}

func runOfflineGate(t *testing.T, ctx context.Context, client *eval.Client, baseURL string, entry offlineCorpus) {
	corpus, err := eval.LoadCorpus(entry.path)
	if err != nil {
		t.Fatal(err)
	}
	current, err := gate.Measure(ctx, client, corpus)
	if err != nil {
		t.Fatal(err)
	}
	violations := gate.CheckFloors(current, entry.floors)
	raw, err := os.ReadFile(entry.baseline)
	switch {
	case err == nil:
		var baseline gate.Snapshot
		if err := json.Unmarshal(raw, &baseline); err != nil {
			t.Fatal(err)
		}
		violations = append(violations, gate.Compare(&baseline, current, corpus)...)
	case errors.Is(err, fs.ErrNotExist) && *updateBaseline:
		// A new corpus version starts its own baseline; floors still apply.
	default:
		t.Fatalf("baseline %s: %v", entry.baseline, err)
	}
	if *evalReportDir != "" {
		if err := os.MkdirAll(*evalReportDir, 0700); err != nil {
			t.Fatal(err)
		}
		writeGateJSON(t, filepath.Join(*evalReportDir, entry.artifact+"current.json"), current)
		writeGateJSON(t, filepath.Join(*evalReportDir, entry.artifact+"gate.json"), struct {
			Passed     bool     `json:"passed"`
			Violations []string `json:"violations"`
		}{len(violations) == 0, violations})
	}
	for _, violation := range violations {
		t.Error(violation)
	}
	if group, ok := current.Groups["prompt_injection"]["fr"]; ok {
		t.Logf("%s prompt_injection/fr counts=%+v recall=%v fpr=%v", corpus.Header.Name, group.Counts, group.Metrics.Recall, group.Metrics.FPR)
	}
	// Cross-check the per-case runner against the original whole-corpus CLI.
	code, stdout, stderr := runEval(t, nil, "run", "--corpus", entry.path, "--base-url", baseURL, "--format", "json")
	if code != eval.ExitOK {
		t.Fatalf("CLI exit %d: %s", code, stderr)
	}
	report := decodeReport(t, stdout)
	for detector, result := range report.Corpora[0].Detectors {
		if !reflect.DeepEqual(result.GroupResult, current.Groups[detector]["all"]) {
			t.Fatalf("CLI total differs for %s", detector)
		}
		for lang, group := range result.ByLanguage {
			if !reflect.DeepEqual(group, current.Groups[detector][lang]) {
				t.Fatalf("CLI language group differs for %s/%s", detector, lang)
			}
		}
	}
	repeated, err := gate.Measure(ctx, client, corpus)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(current)
	second, _ := json.Marshal(repeated)
	if string(first) != string(second) {
		t.Fatal("snapshot is not byte stable")
	}
	if *updateBaseline && len(violations) == 0 {
		writeGateJSON(t, entry.baseline, current)
	}
}

func writeGateJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
