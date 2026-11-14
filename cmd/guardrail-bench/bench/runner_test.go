package bench

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeSidecar serves the scores contract and reports the 86M ready label.
func fakeSidecar(score float64) *httptest.Server {
	model, _ := LookupModel(CascadePrimary)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready", "model": model.ReadyLabel()})
			return
		}
		var body struct {
			Texts []string `json:"texts"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		scores := make([]float64, len(body.Texts))
		for i := range scores {
			scores[i] = score
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scores": scores})
	}))
}

func TestRulesAndClassifierRunsThroughTheRealService(t *testing.T) {
	root := repoRoot(t)
	cache := t.TempDir()
	rules, err := Run(context.Background(), RunConfig{Root: root, Corpus: CorpusCalibration, Mode: ModeRules, CacheDir: cache, RunID: "rules"})
	if err != nil {
		t.Fatal(err)
	}
	sidecar := fakeSidecar(0.95)
	defer sidecar.Close()
	union, err := Run(context.Background(), RunConfig{Root: root, Corpus: CorpusCalibration, Mode: ModeUnion, Model: CascadePrimary,
		SidecarURL: sidecar.URL, Threshold: 0.9, CacheDir: cache, RunID: "union", Warmup: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.Cases) != 80 || len(union.Cases) != 80 || len(union.Warmup) != 1 {
		t.Fatalf("cases %d/%d warmup %d", len(rules.Cases), len(union.Cases), len(union.Warmup))
	}
	for i, item := range union.Cases {
		if item.Status != StatusOK || item.Score == nil || *item.Score != 0.95 || !item.Semantic || item.Decision != "BLOCKED" {
			t.Fatalf("union case %s: %+v", item.ID, item)
		}
		if item.Rules != rules.Cases[i].Rules {
			t.Fatalf("case %s: rules differ between runs", item.ID)
		}
	}
	if _, err := consistency(union); err != nil {
		t.Fatal(err)
	}
	// Replay answers from the cache without the sidecar: same decisions, no upstream.
	replay, err := Run(context.Background(), RunConfig{Root: root, Corpus: CorpusCalibration, Mode: ModeUnion, Model: CascadePrimary,
		Threshold: 0.9, CacheDir: cache, RunID: "replay"})
	if err != nil {
		t.Fatal(err)
	}
	if replay.Sidecar.Upstream != 0 || replay.Sidecar.CacheHits != 80 {
		t.Fatalf("replay stats %+v", replay.Sidecar)
	}
}

func TestCascadeRoutesOnlyTheGrayZoneToTheJudge(t *testing.T) {
	root := repoRoot(t)
	protocol := &Protocol{DefaultThreshold: DefaultThreshold, Models: []ModelThreshold{{Name: CascadePrimary, Threshold: 0.6}}, Zone: ZoneProtocol{Lower: 0.4, Upper: 0.6}, Jev: frozenJev()}
	for _, score := range []float64{0.5, 0.95} {
		sidecar := fakeSidecar(score)
		cacheDir := t.TempDir()
		if _, err := Run(context.Background(), RunConfig{Root: root, Corpus: CorpusTest, Mode: ModeUnion, Model: CascadePrimary, SidecarURL: sidecar.URL,
			Threshold: 0.6, CacheDir: cacheDir, Protocol: protocol, RunID: "record"}); err != nil {
			t.Fatal(err)
		}
		sidecar.Close()
		fake := &fakeJev{}
		upstream := httptest.NewServer(fake)
		if _, err := Run(context.Background(), RunConfig{Root: root, Corpus: CorpusTest, Mode: ModeJudge, JevLive: true, JevKey: []byte(testKey),
			JevUpstream: upstream.URL + "/v1/systemone", JevClient: upstream.Client(), Budget: DefaultBudget, CacheDir: cacheDir,
			Protocol: protocol, RunID: "judge"}); err != nil {
			t.Fatal(err)
		}
		calls := fake.calls.Load()
		upstream.Close()
		cascade, err := Run(context.Background(), RunConfig{Root: root, Corpus: CorpusTest, Mode: ModeCascade, Model: CascadePrimary,
			Threshold: 0.6, Zone: &Zone{Lower: 0.4, Upper: 0.6}, CacheDir: cacheDir, Protocol: protocol, RunID: "cascade"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := consistency(cascade); err != nil {
			t.Fatal(err)
		}
		judged := 0
		for _, item := range cascade.Cases {
			if item.JudgeCalls > 0 {
				judged++
			}
		}
		if cascade.Judge.Upstream != 0 {
			t.Fatal("the cascade made a judge call")
		}
		// Score 0.5 is in the zone: every case but the egress-blocked one is judged
		// from the cache (noul 0.12 < 0.7, so not detected). Score 0.95 is above
		// the zone: the classifier decides and the judge is never asked.
		switch score {
		case 0.5:
			if judged != 160 || cascade.Judge.CacheHits != int(calls) {
				t.Fatalf("in zone: judged %d, cache hits %d of %d", judged, cascade.Judge.CacheHits, calls)
			}
		default:
			if judged != 0 {
				t.Fatalf("above zone: judged %d", judged)
			}
		}
	}
}
