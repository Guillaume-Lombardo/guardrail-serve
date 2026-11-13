package eval_test

import (
	"context"
	"encoding/json"
	"flag"
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

const baselinePath = "baseline/original-v1.json"

func TestOfflineRegressionGate(t *testing.T) {
	// Synchronous httptest startup owns an OS-assigned loopback listener:
	// no port race, subprocess, readiness sleep, environment or model provider.
	server := startService(t, config.Config{})
	corpus, err := eval.LoadCorpus(originalCorpus)
	if err != nil {
		t.Fatal(err)
	}
	client, err := eval.NewClient(eval.ClientConfig{BaseURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	current, err := gate.Measure(ctx, client, corpus)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	var baseline gate.Snapshot
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	violations := gate.Compare(&baseline, current, corpus)
	if *evalReportDir != "" {
		if err := os.MkdirAll(*evalReportDir, 0700); err != nil {
			t.Fatal(err)
		}
		writeGateJSON(t, filepath.Join(*evalReportDir, "current.json"), current)
		writeGateJSON(t, filepath.Join(*evalReportDir, "gate.json"), struct {
			Passed     bool     `json:"passed"`
			Violations []string `json:"violations"`
		}{len(violations) == 0, violations})
	}
	for _, violation := range violations {
		t.Error(violation)
	}
	// Cross-check the per-case runner against the original whole-corpus CLI.
	code, stdout, stderr := runEval(t, nil, "run", "--corpus", originalCorpus, "--base-url", server.URL, "--format", "json")
	if code != eval.ExitOK {
		t.Fatalf("CLI exit %d: %s", code, stderr)
	}
	report := decodeReport(t, stdout)
	for detector, entry := range report.Corpora[0].Detectors {
		if !reflect.DeepEqual(entry.GroupResult, current.Groups[detector]["all"]) {
			t.Fatalf("CLI total differs for %s", detector)
		}
		for lang, group := range entry.ByLanguage {
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
		writeGateJSON(t, baselinePath, current)
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
