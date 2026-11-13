package eval_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

func TestConfusionCountsAndMetrics(t *testing.T) {
	var c eval.Confusion
	for _, o := range []struct{ expected, detected bool }{
		{true, true}, {true, true}, {true, true}, // TP 3
		{false, true},                                                  // FP 1
		{false, false}, {false, false}, {false, false}, {false, false}, // TN 4
		{true, false}, // FN 1
	} {
		c.Add(o.expected, o.detected)
	}
	if c != (eval.Confusion{TP: 3, FP: 1, TN: 4, FN: 1}) || c.Total() != 9 {
		t.Fatalf("confusion = %+v", c)
	}
	m := c.Metrics()
	for name, tc := range map[string]struct {
		got  eval.Ratio
		want float64
	}{"precision": {m.Precision, 0.75}, "recall": {m.Recall, 0.75}, "fpr": {m.FPR, 0.2}} {
		if !tc.got.Defined || math.Abs(tc.got.Value-tc.want) > 1e-12 {
			t.Errorf("%s = %+v, want %v", name, tc.got, tc.want)
		}
	}
}

func TestZeroDenominatorsAreUndefinedNotNaN(t *testing.T) {
	for name, tc := range map[string]struct {
		c                    eval.Confusion
		precision, recall, f bool // defined?
	}{
		"empty":            {eval.Confusion{}, false, false, false},
		"only negatives":   {eval.Confusion{TN: 5}, false, false, true},
		"only positives":   {eval.Confusion{FN: 2}, false, true, false},
		"all detected":     {eval.Confusion{TP: 2}, true, true, false},
		"only false alarm": {eval.Confusion{FP: 1}, true, false, true},
	} {
		m := tc.c.Metrics()
		if m.Precision.Defined != tc.precision || m.Recall.Defined != tc.recall || m.FPR.Defined != tc.f {
			t.Errorf("%s: %+v", name, m)
		}
		for _, r := range []eval.Ratio{m.Precision, m.Recall, m.FPR} {
			if !r.Defined && r.Value != 0 {
				t.Errorf("%s: undefined ratio must be 0, got %v", name, r.Value)
			}
		}
		encoded, err := json.Marshal(m)
		if err != nil || strings.Contains(string(encoded), "NaN") {
			t.Errorf("%s: %s %v", name, encoded, err)
		}
	}
}

func TestMergeSumsCounts(t *testing.T) {
	a := eval.Confusion{TP: 1, FP: 2, TN: 3, FN: 4}
	a.Merge(eval.Confusion{TP: 10, FP: 20, TN: 30, FN: 40})
	if a != (eval.Confusion{TP: 11, FP: 22, TN: 33, FN: 44}) {
		t.Fatalf("merge = %+v", a)
	}
}
