// Package eval_test runs the evaluation command against the real service
// handler (in process, over a loopback httptest server) with the shipped
// corpus. It checks contracts and invariants, never detection quality
// thresholds: those belong to the regression gate, not to this test.
package eval_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
)

const originalCorpus = "corpus/guardrail-serve-original-v1.jsonl"

func startService(t *testing.T, cfg config.Config) *httptest.Server {
	t.Helper()
	cfg.SecretMask, cfg.LiteLLMDefaultPolicy = "[REDACTED]", "detect_secret"
	cfg.MaxTextItems, cfg.MaxTextChars = 20, 20000
	handler, err := app.NewHandlerWithLogger(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func runEval(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := eval.Main(context.Background(), args, func(key string) string { return env[key] }, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func decodeReport(t *testing.T, raw string) eval.Report {
	t.Helper()
	var report eval.Report
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatalf("report: %v\n%s", err, raw)
	}
	return report
}

func TestShippedCorpusIsValidAndCanonical(t *testing.T) {
	data, err := os.ReadFile(originalCorpus)
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := eval.ParseCorpus(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var canonical bytes.Buffer
	if err := eval.WriteCorpus(&canonical, corpus.Header, corpus.Cases); err != nil {
		t.Fatal(err)
	}
	if canonical.String() != string(data) {
		t.Fatal("corpus is not in canonical form; regenerate it with eval.WriteCorpus")
	}

	// Every detector has positives and negatives in both languages.
	type key struct{ detector, lang string }
	positives, negatives := map[key]int{}, map[key]int{}
	for _, item := range corpus.Cases {
		for detector, expected := range item.Labels {
			if expected {
				positives[key{detector, item.Lang}]++
			} else {
				negatives[key{detector, item.Lang}]++
			}
		}
	}
	for _, detector := range []string{"detect_secret", "detect_pii", "prompt_injection"} {
		for _, lang := range []string{"fr", "en"} {
			if positives[key{detector, lang}] < 3 || negatives[key{detector, lang}] < 3 {
				t.Errorf("%s/%s: %d positives, %d negatives", detector, lang, positives[key{detector, lang}], negatives[key{detector, lang}])
			}
		}
	}
}

func TestAnnotateAgainstRealService(t *testing.T) {
	server := startService(t, config.Config{})
	code, stdout, stderr := runEval(t, nil, "run", "--corpus", originalCorpus, "--base-url", server.URL, "--mode", "annotate", "--policy", "audit", "--format", "json")
	if code != eval.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	report := decodeReport(t, stdout)
	assertWholeCorpusEvaluated(t, report, report.Run.Cases)
	if report.Run.Requests != report.Run.Cases || len(report.Warnings) != 0 {
		t.Fatalf("run = %+v warnings = %v", report.Run, report.Warnings)
	}
	// The policy route must be able to detect something for every detector.
	for name, detector := range report.Corpora[0].Detectors {
		if detector.Counts.TP == 0 {
			t.Errorf("%s never detected a labelled positive: %+v", name, detector.Counts)
		}
	}
}

func TestEnforceAgainstRealService(t *testing.T) {
	server := startService(t, config.Config{})
	code, stdout, stderr := runEval(t, nil, "run", "--corpus", originalCorpus, "--base-url", server.URL, "--mode", "enforce", "--format", "json")
	if code != eval.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	report := decodeReport(t, stdout)
	assertWholeCorpusEvaluated(t, report, report.Run.Requests)
	for name, detector := range report.Corpora[0].Detectors {
		if detector.Counts.TP == 0 {
			t.Errorf("%s never detected a labelled positive: %+v", name, detector.Counts)
		}
	}
}

// assertWholeCorpusEvaluated checks that no request failed and that each
// detector's counts add up to the number of evaluations it received.
func assertWholeCorpusEvaluated(t *testing.T, report eval.Report, requests int) {
	t.Helper()
	if report.Status != eval.StatusComplete || report.Errors.Total != 0 || report.Run.CasesErrored != 0 {
		t.Fatalf("status = %s errors = %+v", report.Status, report.Errors)
	}
	if len(report.Corpora) != 1 {
		t.Fatalf("corpora = %d, want 1", len(report.Corpora))
	}
	total := 0
	for name, detector := range report.Corpora[0].Detectors {
		if detector.Errored != 0 || detector.Counts.Total() == 0 {
			t.Errorf("%s: %+v", name, detector)
		}
		total += detector.Counts.Total()
	}
	if report.Corpora[0].Aggregate.Micro.Counts.Total() != total {
		t.Errorf("micro total = %d, sum of detectors = %d", report.Corpora[0].Aggregate.Micro.Counts.Total(), total)
	}
	if report.Run.Requests != requests {
		t.Errorf("requests = %d, want %d", report.Run.Requests, requests)
	}
}

func TestPrefixAndAPIKeyAgainstRealService(t *testing.T) {
	const key = "e2e-demo-key-000111"
	cfg := config.Config{APIPrefix: "/api", Runtime: config.Runtime{APIKeys: []string{key}}}
	server := startService(t, cfg)
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"run", "--corpus", originalCorpus, "--base-url", server.URL + "/api", "--format", "json"}

	for name, extra := range map[string][]string{
		"bearer":    {"--api-key-file", keyFile},
		"x-api-key": {"--api-key-file", keyFile, "--auth-scheme", "x-api-key"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runEval(t, nil, append(append([]string{}, base...), extra...)...)
			if code != eval.ExitOK || strings.Contains(stdout+stderr, key) {
				t.Fatalf("exit %d: %s", code, stderr)
			}
		})
	}

	t.Run("missing key aborts on the first rejection", func(t *testing.T) {
		code, stdout, stderr := runEval(t, nil, base...)
		report := decodeReport(t, stdout)
		if code != eval.ExitAborted || report.Run.Requests != 1 || !strings.Contains(stderr, "HTTP 401") {
			t.Fatalf("exit %d requests %d: %s", code, report.Run.Requests, stderr)
		}
	})
	t.Run("wrong key from the environment", func(t *testing.T) {
		code, stdout, stderr := runEval(t, map[string]string{eval.EnvAPIKey: "wrong-key"}, base...)
		if code != eval.ExitAborted || strings.Contains(stdout+stderr, "wrong-key") {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	})
	t.Run("unknown policy is a request error, not a detection", func(t *testing.T) {
		code, stdout, _ := runEval(t, map[string]string{eval.EnvAPIKey: key}, append(append([]string{}, base...), "--policy", "no-such-policy", "--max-consecutive-errors", "0")...)
		report := decodeReport(t, stdout)
		if code != eval.ExitRequestErrors || report.Errors.ByKind["http_status"] != report.Run.Cases || report.Corpora[0].Aggregate.Micro.Counts.Total() != 0 {
			t.Fatalf("exit %d report %+v", code, report.Errors)
		}
	})
}
