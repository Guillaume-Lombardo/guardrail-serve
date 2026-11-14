package bench

import (
	"strings"
	"testing"
)

// testRun builds a bench-test run where decide(i) gives (rules, semantic) for case i.
// Cases 0-9 are attacks, 10-29 benign texts.
func testRun(id string, mode Mode, model string, threshold float64, decide func(i int) (bool, bool, float64)) RunFile {
	run := RunFile{Format: RunFormat, Version: FormatVersion, RunID: id, Mode: mode, Model: model, Corpus: CorpusTest, ProtocolSHA256: "p"}
	if mode == ModeUnion || mode == ModeCascade {
		run.SemanticThreshold = &threshold
	}
	if mode.usesJudge() {
		run.Jev = &JevSettings{ProxyMode: "cache"}
	}
	for i := 0; i < 30; i++ {
		rules, semantic, score := decide(i)
		item := CaseResult{ID: string(rune('A' + i)), Lang: "fr", Label: i < 10, Status: StatusOK, Rules: rules, Semantic: semantic, Decision: "NONE"}
		if rules || semantic {
			item.Decision = "BLOCKED"
		}
		if mode == ModeUnion {
			item.Score = &score
		}
		if mode == ModeJudge {
			item.JudgeCalls, item.JudgeTokens = 1, 1000
		}
		run.Cases = append(run.Cases, item)
	}
	return run
}

func TestReportComputesD1AgainstTheReference(t *testing.T) {
	ruleHit := func(i int) bool { return i < 3 }
	reference := testRun("ref", ModeUnion, CascadePrimary, 0.9, func(i int) (bool, bool, float64) {
		// 6 attacks caught by the model, 5 benign flagged.
		score := 0.1
		if (i >= 3 && i < 6) || (i >= 10 && i < 15) {
			score = 0.95
		}
		return ruleHit(i), score >= 0.9, score
	})
	better := testRun("better", ModeUnion, "pg2-22m", 0.8, func(i int) (bool, bool, float64) {
		score := 0.1
		if (i >= 3 && i < 8) || i == 10 {
			score = 0.85
		}
		return ruleHit(i), score >= 0.8, score
	})
	judge := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return ruleHit(i), i < 9, 0 })
	judge.Cases[29].Status, judge.Cases[29].ErrorKind, judge.Cases[29].Rules, judge.Cases[29].Semantic, judge.Cases[29].Decision = StatusError, "http_502", false, false, ""
	bundle := &Bundle{Format: BundleFormat, Version: FormatVersion, ProtocolSHA256: "p", Runs: []RunFile{reference, better, judge}}
	results, err := Report(bundle, &Protocol{}, "p")
	if err != nil {
		t.Fatal(err)
	}
	if results.Decision.MaxFP != 1 { // floor(5% of 20)
		t.Fatalf("max FP %d", results.Decision.MaxFP)
	}
	byConfig := map[string]Row{}
	for _, row := range results.Rows {
		byConfig[row.Config] = row
	}
	ref := byConfig[ReferenceConfig()]
	if ref.Counts != (Counts{TP: 6, FN: 4, FP: 5, TN: 15}) || ref.D1 == nil || *ref.D1 {
		t.Fatalf("reference row %+v", ref)
	}
	chain := byConfig["rules+pg2-22m@0.8"]
	if chain.Counts.TP != 8 || chain.Counts.FP != 1 || chain.D1 == nil || !*chain.D1 {
		t.Fatalf("better chain %+v", chain)
	}
	if model := byConfig["pg2-22m@0.8"]; model.D1 != nil || model.Counts.TP != 5 {
		t.Fatalf("model-alone rows are not D1 candidates: %+v", model)
	}
	rj := byConfig[ComponentRulesJ]
	// 9 of 10 attacks, 0 FP, but one errored benign text counts against D1 only if it pushes FP over.
	if rj.Counts.Errors != 1 || rj.ErrorsNegative != 1 || rj.Counts.FP != 0 || rj.D1 == nil || !*rj.D1 {
		t.Fatalf("rules+judge %+v", rj)
	}
	if rj.USDPer1000 == nil {
		t.Fatal("no cost per 1000 requests")
	}
	near(t, "USD per 1000 requests of 1000 tokens each", *rj.USDPer1000, 1000*CostUSD(1000))
	if !results.Decision.ChangeDefault || strings.Join(results.Decision.Passing, ",") != "rules+judge,rules+pg2-22m@0.8" {
		t.Fatalf("decision %+v", results.Decision)
	}
	if !strings.Contains(Markdown(results), "| rules+pg2-22m@0.8 | all | 8 | 1 | 19 | 2 |") {
		t.Fatalf("markdown:\n%s", Markdown(results))
	}
}

func TestReportRefusesInconsistentOrForeignRuns(t *testing.T) {
	good := testRun("ref", ModeUnion, CascadePrimary, 0.9, func(i int) (bool, bool, float64) { return false, false, 0.1 })
	bad := testRun("bad", ModeUnion, "pg2-22m", 0.9, func(i int) (bool, bool, float64) { return false, i == 0, 0.1 })
	if _, err := Report(&Bundle{Format: BundleFormat, Version: FormatVersion, ProtocolSHA256: "p", Runs: []RunFile{good, bad}}, &Protocol{}, "p"); err == nil ||
		!strings.Contains(err.Error(), "score >= threshold") {
		t.Fatalf("inconsistent semantic decision: %v", err)
	}
	foreign := good
	foreign.ProtocolSHA256 = "other"
	if _, err := Report(&Bundle{Format: BundleFormat, Version: FormatVersion, ProtocolSHA256: "p", Runs: []RunFile{foreign}}, &Protocol{}, "p"); err == nil {
		t.Fatal("a run measured under another protocol was accepted")
	}
	judge := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, false, 0 })
	judge.Corpus = CorpusCalibration
	if _, err := Report(&Bundle{Format: BundleFormat, Version: FormatVersion, ProtocolSHA256: "p", Runs: []RunFile{good, judge}}, &Protocol{}, "p"); err == nil {
		t.Fatal("a judge run on calibration was accepted")
	}
}
