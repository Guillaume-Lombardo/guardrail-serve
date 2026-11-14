package bench

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// TestJudgeWireCarriesNoSensitiveFixtureValue runs the real service in
// judge_only mode over the whole bench-test split against a fake System One and
// checks every byte that would leave the host: the #24 masking runs before
// egress, the proxy guard refuses what masking missed, and no raw sensitive
// value of the synthetic secret and PII cases reaches the upstream.
func TestJudgeWireCarriesNoSensitiveFixtureValue(t *testing.T) {
	root := repoRoot(t)
	fake := &fakeJev{}
	upstream := httptest.NewServer(fake)
	defer upstream.Close()
	protocol := &Protocol{DefaultThreshold: DefaultThreshold}
	var logs strings.Builder
	run, err := Run(context.Background(), RunConfig{
		Root: root, Corpus: CorpusTest, Mode: ModeJudge, JevLive: true, JevKey: []byte(testKey),
		JevUpstream: upstream.URL + "/v1/systemone", JevClient: upstream.Client(), Budget: DefaultBudget,
		CacheDir: t.TempDir(), Protocol: protocol, RunID: "wire", LogOutput: &logs,
	})
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := LoadCorpus(root, CorpusTest)
	if err != nil {
		t.Fatal(err)
	}
	var sensitive []string
	for _, item := range corpus.Cases {
		for _, pattern := range leakPatterns {
			sensitive = append(sensitive, pattern.re.FindAllString(item.Text, -1)...)
		}
	}
	if len(sensitive) < 7 {
		t.Fatalf("only %d raw sensitive values found: the fixture check would be vacuous", len(sensitive))
	}
	// Known masking limit: the all-zero demonstration card number of sb-0100 is
	// not masked by detect_pii, so the egress guard refuses that one request and
	// the case is an error (never a detection). Every other case reaches the judge.
	blocked := map[string]bool{"sb-0100": true}
	if run.Judge.EgressBlocked != len(blocked) || !strings.Contains(logs.String(), "card:1") {
		t.Fatalf("egress guard blocked %d request(s) (%s), want only the demonstration card", run.Judge.EgressBlocked, strings.TrimSpace(logs.String()))
	}
	if got := len(fake.bodies); got != len(corpus.Cases)-len(blocked) {
		t.Fatalf("%d upstream bodies for %d cases", got, len(corpus.Cases))
	}
	for i, body := range fake.bodies {
		if kinds := LeakKinds(body); len(kinds) > 0 {
			t.Errorf("body %d carries %v", i, kinds)
		}
		for _, value := range sensitive {
			if strings.Contains(body, value) {
				t.Errorf("body %d carries a raw fixture value of %d bytes", i, len(value))
			}
		}
		if strings.Contains(body, DummyJudgeKey) || strings.Contains(body, testKey) {
			t.Errorf("body %d carries a key", i)
		}
		if fake.headers[i] != "Bearer "+testKey {
			t.Errorf("request %d did not use the proxy key", i)
		}
	}
	for _, item := range run.Cases {
		if blocked[item.ID] {
			if item.Status != StatusError || item.ErrorKind != "http_502" || item.JudgeCache != "egress_blocked" {
				t.Fatalf("blocked case %s: %+v", item.ID, item)
			}
			continue
		}
		if item.Status != StatusOK || item.JudgeCalls != 1 || item.JudgeProb == nil {
			t.Fatalf("case %s: %+v", item.ID, item)
		}
	}
}
