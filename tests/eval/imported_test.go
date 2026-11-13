package eval_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/tests/eval/loaders"
)

// TestImportedFixturesRunAlongsideTheOriginalCorpus exercises the whole
// pipeline offline: import small fixtures shaped like the public datasets,
// then evaluate them together with the shipped corpus against the real service.
func TestImportedFixturesRunAlongsideTheOriginalCorpus(t *testing.T) {
	dir := filepath.Join(t.TempDir(), loaders.ScratchDir)
	imports := map[string][]string{
		"bipia.jsonl":     {"--dataset", "bipia", "--input", "loaders/testdata/bipia_attack_sample.json"},
		"presidio.jsonl":  {"--dataset", "presidio", "--input", "loaders/testdata/presidio_sample.json"},
		"agentdojo.jsonl": {"--dataset", "agentdojo", "--input", "loaders/testdata/agentdojo"},
	}
	args := []string{"run", "--corpus", originalCorpus, "--mode", "annotate", "--format", "json"}
	for file, importArgs := range imports {
		output := filepath.Join(dir, file)
		var stdout, stderr strings.Builder
		if code := loaders.Main(t.Context(), append(importArgs, "--output", output), &stdout, &stderr); code != loaders.ExitOK {
			t.Fatalf("import %s: %d %s", file, code, stderr.String())
		}
		args = append(args, "--corpus", output)
	}

	server := startService(t, config.Config{})
	code, stdout, stderr := runEval(t, nil, append(args, "--base-url", server.URL)...)
	if code != eval.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	report := decodeReport(t, stdout)
	if len(report.Corpora) != 4 || report.Status != eval.StatusComplete {
		t.Fatalf("report = %+v", report)
	}
	// Each corpus is reported on its own: imported labels are never pooled.
	byName := map[string]eval.CorpusInfo{}
	for _, corpus := range report.Corpora {
		byName[corpus.Name] = corpus
	}
	if got := byName["presidio"].Detectors["detect_pii"].Counts.Total(); got != 3 {
		t.Fatalf("presidio cases = %d", got)
	}
	if got := byName["guardrail-serve-original-v1"].Detectors["detect_pii"].Counts.Total(); got == 0 {
		t.Fatal("original corpus lost its own totals")
	}
	if got := byName["bipia"].Detectors["prompt_injection"].Counts.Total(); got != 3 {
		t.Fatalf("bipia cases = %d", got)
	}

	var text strings.Builder
	if err := report.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"== bipia ==", "== presidio ==", "== guardrail-serve-original-v1 =="} {
		if !strings.Contains(text.String(), section) {
			t.Fatalf("text report lacks section %q:\n%s", section, text.String())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "bipia.jsonl")); err != nil {
		t.Fatal(err)
	}
}
