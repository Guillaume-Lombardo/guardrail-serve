package bench

import (
	"math"
	"testing"
)

func near(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 5e-4 {
		t.Fatalf("%s = %.6f, want %.6f", name, got, want)
	}
}

func TestWilsonInterval(t *testing.T) {
	zero := Wilson(0, 80)
	near(t, "0/80 low", zero.Low, 0)
	near(t, "0/80 high", zero.High, 0.0458)
	half := Wilson(5, 10)
	near(t, "5/10 low", half.Low, 0.2366)
	near(t, "5/10 high", half.High, 0.7634)
	if empty := Wilson(0, 0); empty.Defined || empty.Value != 0 {
		t.Fatalf("empty denominator must be undefined, got %+v", empty)
	}
}

func TestCountsNeverCountErrorsAsDetections(t *testing.T) {
	var counts Counts
	counts.Add(true, true)
	counts.Add(true, false)
	counts.Add(false, true)
	counts.Add(false, false)
	counts.Errors++
	if counts.TP != 1 || counts.FN != 1 || counts.FP != 1 || counts.TN != 1 {
		t.Fatalf("confusion matrix %+v", counts)
	}
	if counts.Recall().Den != 2 || counts.FPR().Den != 2 {
		t.Fatalf("errors leaked into denominators: %+v %+v", counts.Recall(), counts.FPR())
	}
}

func TestNearestRankPercentiles(t *testing.T) {
	values := make([]float64, 0, 20)
	for i := 20; i >= 1; i-- {
		values = append(values, float64(i))
	}
	summary := Summarize(values)
	if summary.N != 20 || summary.P50 != 10 || summary.P95 != 19 || summary.Max != 20 {
		t.Fatalf("summary %+v", summary)
	}
	if Summarize(nil).N != 0 {
		t.Fatal("empty input must give N=0")
	}
}

func TestExactMcNemar(t *testing.T) {
	near(t, "0 vs 5", ExactMcNemar(0, 5).PValue, 0.0625)
	near(t, "3 vs 3", ExactMcNemar(3, 3).PValue, 1)
	near(t, "1 vs 9", ExactMcNemar(1, 9).PValue, 0.02148)
	if ExactMcNemar(0, 0).PValue != 1 {
		t.Fatal("no discordant pair must give p=1")
	}
}

func TestCostIsTheInputTokenPrice(t *testing.T) {
	near(t, "1M tokens", CostUSD(1_000_000), 0.042)
	near(t, "worst case is the documented 64k-token request", WorstCaseUSD(), 64_000*0.042/1e6)
}
