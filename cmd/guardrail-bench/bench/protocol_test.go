package bench

import (
	"strings"
	"testing"
)

func ptr(v float64) *float64 { return &v }

func TestSelectThresholdIsTheLowestCandidateWithinBudget(t *testing.T) {
	cases := []scored{
		{label: true, score: 0.95}, {label: true, score: 0.4}, {label: true, score: 0.2},
		{label: false, score: 0.9}, {label: false, score: 0.5}, {label: false, score: 0.3}, {label: false, score: 0.1},
	}
	threshold, rule, candidates, err := SelectThreshold(cases, 2)
	if err != nil || rule != RuleR1 {
		t.Fatalf("threshold %v rule %s err %v", threshold, rule, err)
	}
	// At 0.4 negatives 0.9 and 0.5 fire (2 FP): the lowest candidate with FP <= 2.
	if threshold != 0.4 {
		t.Fatalf("threshold = %v, want 0.4", threshold)
	}
	if candidates != 8 { // 7 distinct scores + 1.0
		t.Fatalf("candidates = %d", candidates)
	}
	// Inclusive >=: a negative exactly at the threshold counts as a false positive.
	threshold, _, _, _ = SelectThreshold(cases, 0)
	if threshold != 0.95 {
		t.Fatalf("budget 0 threshold = %v, want 0.95", threshold)
	}
}

func TestSelectThresholdCountsRuleFalsePositives(t *testing.T) {
	cases := []scored{
		{label: true, score: 0.6}, {label: false, rules: true, score: 0.1}, {label: false, rules: true, score: 0.2},
		{label: false, score: 0.5}, {label: false, score: 0.55},
	}
	threshold, rule, _, _ := SelectThreshold(cases, 2)
	if rule != RuleR1 || threshold != 0.6 {
		t.Fatalf("got %v %s, want 0.6 R1 (rules already use the whole budget)", threshold, rule)
	}
	cases = append(cases, scored{label: false, rules: true, score: 0.05})
	threshold, rule, _, _ = SelectThreshold(cases, 2)
	if rule != RuleR1Fallback || threshold != 0.5 {
		t.Fatalf("got %v %s, want 0.5 with the model-alone fallback", threshold, rule)
	}
}

func TestSelectZoneBoundsTheShareOfTextsInclusively(t *testing.T) {
	var cases []scored
	for _, score := range []float64{0.01, 0.02, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.99} {
		cases = append(cases, scored{score: score})
	}
	zone, err := SelectZone(cases, 0.6, 3)
	if err != nil {
		t.Fatal(err)
	}
	// [0.4, 0.6] holds 0.4, 0.5 and 0.6: three texts, both bounds inclusive.
	if zone.Lower != 0.4 || zone.Upper != 0.6 || zone.TextsInZone != 3 {
		t.Fatalf("zone %+v", zone)
	}
}

func calibrationRun(id, model string, scores []float64, labels, rules []bool) *RunFile {
	run := &RunFile{Format: RunFormat, Version: FormatVersion, RunID: id, Mode: ModeUnion, Model: model, Corpus: CorpusCalibration, CorpusSHA256: "c"}
	if model == "" {
		run.Mode = ModeRules
	}
	for i := range labels {
		item := CaseResult{ID: string(rune('a' + i)), Label: labels[i], Rules: rules[i], Status: StatusOK}
		if scores != nil {
			item.Score = ptr(scores[i])
		}
		run.Cases = append(run.Cases, item)
	}
	return run
}

func TestCalibrateFreezesEveryModelAndTheZone(t *testing.T) {
	labels := []bool{true, true, false, false, false}
	rules := []bool{true, false, false, false, false}
	rulesRun := calibrationRun("rules", "", nil, labels, rules)
	var runs []*RunFile
	for _, model := range Models {
		scores := []float64{0.9, 0.8, 0.7, 0.2, 0.1}
		if model.Kind == KindGenerative {
			scores = []float64{1, 0, 0, 0, 0}
		}
		runs = append(runs, calibrationRun(model.Name, model.Name, scores, labels, rules))
	}
	protocol, err := Calibrate(rulesRun, runs, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if protocol.Negatives != 3 || protocol.FPBudget != 0 {
		t.Fatalf("negatives %d budget %d", protocol.Negatives, protocol.FPBudget)
	}
	primary, _ := protocol.Model(CascadePrimary)
	if primary.Threshold != 0.8 || primary.Rule != RuleR1 {
		t.Fatalf("primary %+v", primary)
	}
	qwen, _ := protocol.Model("qwen3guard-0.6b")
	if qwen.Threshold != GenerativeThreshold || qwen.Rule != RuleBinary {
		t.Fatalf("generative %+v", qwen)
	}
	if protocol.Zone.Upper != 0.8 || protocol.Zone.Lower != 0.8 || protocol.Zone.TextsInZone != 1 {
		t.Fatalf("zone %+v", protocol.Zone)
	}
	if err := protocol.AllowedThreshold(CascadePrimary, 0.9); err != nil {
		t.Fatalf("current threshold of the primary must be allowed: %v", err)
	}
	if err := protocol.AllowedThreshold("pg2-22m", 0.9); err == nil {
		t.Fatal("a threshold that is not frozen must be refused")
	}
}

func TestCalibrateRefusesErroredCasesAndMissingModels(t *testing.T) {
	labels := []bool{true, false}
	rules := []bool{false, false}
	rulesRun := calibrationRun("rules", "", nil, labels, rules)
	run := calibrationRun("pg2-86m", "pg2-86m", []float64{0.9, 0.1}, labels, rules)
	run.Cases[1].Status, run.Cases[1].ErrorKind = StatusError, "http_502"
	if _, err := Calibrate(rulesRun, []*RunFile{run}, nil); err == nil || !strings.Contains(err.Error(), "errored") {
		t.Fatalf("errored case: %v", err)
	}
	run = calibrationRun("pg2-86m", "pg2-86m", []float64{0.9, 0.1}, labels, rules)
	if _, err := Calibrate(rulesRun, []*RunFile{run}, nil); err == nil || !strings.Contains(err.Error(), "covers") {
		t.Fatalf("missing models: %v", err)
	}
}

func TestRunConfigEnforcesTheProtocol(t *testing.T) {
	protocol := &Protocol{DefaultThreshold: 0.9, Models: []ModelThreshold{{Name: "pg2-86m", Threshold: 0.7}}, Zone: ZoneProtocol{Lower: 0.5, Upper: 0.7}}
	base := RunConfig{CacheDir: t.TempDir()}
	for name, cfg := range map[string]RunConfig{
		"judge on calibration": {Corpus: CorpusCalibration, Mode: ModeJudge},
		"judge on history":     {Corpus: CorpusFrench, Mode: ModeJudge, Protocol: protocol},
		"test without freeze":  {Corpus: CorpusTest, Mode: ModeUnion, Model: "pg2-86m", Threshold: 0.7},
		"unfrozen threshold":   {Corpus: CorpusTest, Mode: ModeUnion, Model: "pg2-86m", Threshold: 0.8, Protocol: protocol},
		"live cascade":         {Corpus: CorpusTest, Mode: ModeCascade, Model: "pg2-86m", Threshold: 0.7, Protocol: protocol, Zone: &Zone{0.5, 0.7}, JevLive: true},
		"other zone":           {Corpus: CorpusTest, Mode: ModeCascade, Model: "pg2-86m", Threshold: 0.7, Protocol: protocol, Zone: &Zone{0.4, 0.7}},
	} {
		cfg.CacheDir = base.CacheDir
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := RunConfig{Corpus: CorpusTest, Mode: ModeCascade, Model: "pg2-86m", Threshold: 0.7, Protocol: protocol, Zone: &Zone{0.5, 0.7}, CacheDir: base.CacheDir}
	if err := ok.Validate(); err != nil {
		t.Fatalf("frozen cascade refused: %v", err)
	}
	current := RunConfig{Corpus: CorpusTest, Mode: ModeUnion, Model: "pg2-86m", Threshold: 0.9, Protocol: protocol, CacheDir: base.CacheDir}
	if err := current.Validate(); err != nil {
		t.Fatalf("current threshold refused: %v", err)
	}
}
