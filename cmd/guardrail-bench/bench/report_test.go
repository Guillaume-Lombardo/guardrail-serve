package bench

import (
	"strings"
	"testing"
)

// testRun builds a bench-test run where decide(i) gives (rules, semantic) for case i.
// Cases 0-9 are attacks, 10-29 benign texts.
func testRun(id string, mode Mode, model string, threshold float64, decide func(i int) (bool, bool, float64)) RunFile {
	run := RunFile{Format: RunFormat, Version: FormatVersion, RunID: id, Mode: mode, Model: model, Corpus: CorpusTest, CorpusSHA256: "c", ProtocolSHA256: "p"}
	if mode == ModeUnion || mode == ModeCascade {
		run.SemanticThreshold = &threshold
	}
	if mode.usesJudge() {
		settings := JevFixed
		settings.ProxyMode = "cache"
		run.Jev = &settings
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
			probability := map[bool]float64{true: 0.9, false: 0.1}[semantic]
			item.JudgeCalls, item.JudgeTokens, item.JudgeProb = 1, 1000, &probability
		}
		run.Cases = append(run.Cases, item)
	}
	return run
}

// testCorpora is the canonical corpus of testRun and a calibration stub.
func testCorpora() map[string]*LoadedCorpus {
	test := &LoadedCorpus{Name: CorpusTest, SHA256: "c"}
	for i := 0; i < 30; i++ {
		test.Cases = append(test.Cases, Case{ID: string(rune('A' + i)), Lang: "fr", Label: i < 10})
	}
	return map[string]*LoadedCorpus{CorpusTest: test, CorpusCalibration: {Name: CorpusCalibration, SHA256: "cal"}}
}

func testProtocol() *Protocol {
	return &Protocol{
		CalibrationSHA256: "cal", DefaultThreshold: DefaultThreshold,
		Models: []ModelThreshold{{Name: CascadePrimary, Threshold: 0.95}, {Name: "pg2-22m", Threshold: 0.8}},
		Jev:    frozenJev(),
	}
}

func frozenJev() JevProtocol {
	return JevProtocol{Model: JevFixed.Model, Question: JevFixed.Question, Threshold: JevFixed.Threshold, Timeout: JevFixed.Timeout, FailureMode: "closed"}
}

func report(runs ...RunFile) (*Results, error) {
	return Report(&Bundle{Format: BundleFormat, Version: FormatVersion, ProtocolSHA256: "p", Runs: runs}, testProtocol(), "p", testCorpora())
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
	results, err := report(reference, better, judge)
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
	bad := testRun("bad", ModeUnion, "pg2-22m", 0.8, func(i int) (bool, bool, float64) { return false, i == 0, 0.1 })
	if _, err := report(good, bad); err == nil || !strings.Contains(err.Error(), "score >= threshold") {
		t.Fatalf("inconsistent semantic decision: %v", err)
	}
	foreign := good
	foreign.ProtocolSHA256 = "other"
	if _, err := report(foreign); err == nil {
		t.Fatal("a run measured under another protocol was accepted")
	}
	judge := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, false, 0 })
	judge.Corpus = CorpusCalibration
	if _, err := report(good, judge); err == nil {
		t.Fatal("a judge run on calibration was accepted")
	}
}

func TestReportRefusesRunsThatAreNotTheCanonicalCorpus(t *testing.T) {
	reference := testRun("ref", ModeUnion, CascadePrimary, 0.9, func(i int) (bool, bool, float64) { return false, false, 0.1 })
	// A candidate keeping one detected attack and one accepted benign text would
	// otherwise reach 100% recall and 0 false positives.
	partial := testRun("partial", ModeUnion, "pg2-22m", 0.8, func(i int) (bool, bool, float64) {
		return false, i == 0, map[bool]float64{true: 0.9, false: 0.1}[i == 0]
	})
	partial.Cases = []CaseResult{partial.Cases[0], partial.Cases[20]}
	repeated := testRun("repeated", ModeUnion, "pg2-22m", 0.8, func(i int) (bool, bool, float64) { return false, false, 0.1 })
	repeated.Cases[1] = repeated.Cases[0]
	relabelled := testRun("relabelled", ModeUnion, "pg2-22m", 0.8, func(i int) (bool, bool, float64) { return false, false, 0.1 })
	relabelled.Cases[0].Label = false
	otherVersion := testRun("other-version", ModeUnion, "pg2-22m", 0.8, func(i int) (bool, bool, float64) { return false, false, 0.1 })
	otherVersion.CorpusSHA256 = "changed"
	for _, run := range []RunFile{partial, repeated, relabelled, otherVersion} {
		if _, err := report(reference, run); err == nil {
			t.Fatalf("run %s was accepted", run.RunID)
		}
	}
}

func TestReportRefusesSettingsOutsideTheProtocol(t *testing.T) {
	reference := testRun("ref", ModeUnion, CascadePrimary, 0.9, func(i int) (bool, bool, float64) { return false, false, 0.1 })
	unfrozen := testRun("unfrozen", ModeUnion, "pg2-22m", 0.7, func(i int) (bool, bool, float64) { return false, false, 0.1 })
	judge := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, false, 0 })
	judge.Jev.Threshold = 0.5
	for _, run := range []RunFile{unfrozen, judge} {
		if _, err := report(reference, run); err == nil {
			t.Fatalf("run %s was accepted", run.RunID)
		}
	}
	if err := testProtocol().CheckJev(JevSettings{Model: "jev-1.13.0", Question: "noul", Threshold: 0.7, Timeout: "10s"}); err == nil {
		t.Fatal("another judge version was accepted")
	}
}

func TestJudgeUseAndCostCountEveryRequest(t *testing.T) {
	judge := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, false, 0 })
	// A billed answer the service rejected: an error, still routed and paid.
	judge.Cases[0].Status, judge.Cases[0].ErrorKind, judge.Cases[0].Decision, judge.Cases[0].JudgeCache = StatusError, "http_502", "", "live"
	row := buildRow(&judge, ComponentJudge, ComponentJudge, "all")
	if row.JudgeFraction.Num != 30 || row.JudgeFraction.Den != 30 || row.JudgeTokens != 30_000 {
		t.Fatalf("judge use %+v, tokens %d", row.JudgeFraction, row.JudgeTokens)
	}
	near(t, "USD per 1000 requests", *row.USDPer1000, 1000*CostUSD(1000))
}

func TestReportRefusesJudgeDecisionsThatDoNotFollowTheProbability(t *testing.T) {
	reference := testRun("ref", ModeUnion, CascadePrimary, 0.9, func(i int) (bool, bool, float64) { return false, false, 0.1 })
	low := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, i == 0, 0 })
	probability := 0.01 // below the frozen 0.7, yet recorded as a detection
	low.Cases[0].JudgeProb = &probability
	missing := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, false, 0 })
	missing.Cases[3].JudgeProb = nil
	unjudged := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, false, 0 })
	unjudged.Cases[4].JudgeCalls, unjudged.Cases[4].JudgeProb = 0, nil
	for name, run := range map[string]RunFile{"low probability": low, "missing probability": missing, "unjudged case": unjudged} {
		if _, err := report(reference, run); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestReportRefusesRepeatedRunsWithAnotherCoverage(t *testing.T) {
	reference := testRun("ref", ModeUnion, CascadePrimary, 0.9, func(i int) (bool, bool, float64) { return false, false, 0.1 })
	judge := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, i < 9, 0 })
	failed := testRun("judge-again", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, false, 0 })
	for i := range failed.Cases {
		failed.Cases[i].Status, failed.Cases[i].ErrorKind, failed.Cases[i].Decision = StatusError, "http_502", ""
	}
	// Otherwise the failed repetition would replace the paired comparison of the first run.
	if _, err := report(reference, judge, failed); err == nil || !strings.Contains(err.Error(), "answered") {
		t.Fatalf("a repetition covering other cases was accepted: %v", err)
	}
	if _, err := report(reference, judge, judgeCopy(judge, "judge-same")); err != nil {
		t.Fatalf("an identical repetition was refused: %v", err)
	}
}

func judgeCopy(run RunFile, id string) RunFile {
	run.RunID = id
	run.Cases = append([]CaseResult(nil), run.Cases...)
	return run
}

func TestUnknownBillingIsPublishedApart(t *testing.T) {
	judge := testRun("judge", ModeJudge, "", 0, func(i int) (bool, bool, float64) { return false, false, 0 })
	judge.Cases[0].Status, judge.Cases[0].ErrorKind, judge.Cases[0].Decision, judge.Cases[0].JudgeTokens = StatusError, "http_502", "", 0
	judge.Cases[0].JudgeUnknownUSD = WorstCaseUSD()
	row := buildRow(&judge, ComponentJudge, ComponentJudge, "all")
	near(t, "unknown billing", row.UnknownUSD, WorstCaseUSD())
	near(t, "billed USD per 1000 requests", *row.USDPer1000, 29*CostUSD(1000)/30*1000)
	if !strings.Contains(Markdown(&Results{Rows: []Row{row}}), "unknown billing") {
		t.Fatal("the Markdown table hides the unknown billing")
	}
}
