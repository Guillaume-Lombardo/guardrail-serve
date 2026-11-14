package bench

import (
	"math"
	"sort"
)

// Counts is a confusion matrix plus the cases that produced no decision.
// Errored cases are never counted as TP, FP, TN or FN.
type Counts struct {
	TP     int `json:"tp"`
	FP     int `json:"fp"`
	TN     int `json:"tn"`
	FN     int `json:"fn"`
	Errors int `json:"errors"`
}

// Add records one decided case.
func (c *Counts) Add(label, detected bool) {
	switch {
	case label && detected:
		c.TP++
	case label:
		c.FN++
	case detected:
		c.FP++
	default:
		c.TN++
	}
}

// Rate is a proportion with its denominator and a 95% Wilson interval. An
// empty denominator is undefined (Defined=false), never NaN.
type Rate struct {
	Num     int     `json:"num"`
	Den     int     `json:"den"`
	Value   float64 `json:"value"`
	Low     float64 `json:"low"`
	High    float64 `json:"high"`
	Defined bool    `json:"defined"`
}

const wilsonZ = 1.959963984540054

// Wilson returns num/den with the 95% Wilson score interval.
func Wilson(num, den int) Rate {
	if den <= 0 {
		return Rate{Num: num, Den: den}
	}
	n := float64(den)
	p := float64(num) / n
	z2 := wilsonZ * wilsonZ
	center := (p + z2/(2*n)) / (1 + z2/n)
	half := wilsonZ * math.Sqrt(p*(1-p)/n+z2/(4*n*n)) / (1 + z2/n)
	return Rate{Num: num, Den: den, Value: p, Low: math.Max(0, center-half), High: math.Min(1, center+half), Defined: true}
}

// Recall is TP / (TP + FN).
func (c Counts) Recall() Rate { return Wilson(c.TP, c.TP+c.FN) }

// FPR is FP / (FP + TN).
func (c Counts) FPR() Rate { return Wilson(c.FP, c.FP+c.TN) }

// Latency summarizes durations in milliseconds with nearest-rank percentiles.
type Latency struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	Max float64 `json:"max_ms"`
}

// Summarize computes nearest-rank p50/p95 and the maximum. Empty input gives N=0.
func Summarize(values []float64) Latency {
	if len(values) == 0 {
		return Latency{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	rank := func(q float64) float64 {
		index := int(math.Ceil(q*float64(len(sorted)))) - 1
		return sorted[max(0, min(len(sorted)-1, index))]
	}
	return Latency{N: len(sorted), P50: rank(0.50), P95: rank(0.95), Max: sorted[len(sorted)-1]}
}

// McNemar is an exact two-sided McNemar test on paired binary decisions:
// OnlyA counts cases where A is right and B wrong, OnlyB the reverse.
type McNemar struct {
	OnlyA  int     `json:"only_a"`
	OnlyB  int     `json:"only_b"`
	PValue float64 `json:"p_value"`
}

// ExactMcNemar returns the two-sided binomial p-value of the discordant pairs.
func ExactMcNemar(onlyA, onlyB int) McNemar {
	n := onlyA + onlyB
	result := McNemar{OnlyA: onlyA, OnlyB: onlyB, PValue: 1}
	if n == 0 {
		return result
	}
	k := min(onlyA, onlyB)
	tail := 0.0
	for i := 0; i <= k; i++ {
		tail += math.Exp(logChoose(n, i) - float64(n)*math.Ln2)
	}
	result.PValue = math.Min(1, 2*tail)
	return result
}

func logChoose(n, k int) float64 {
	a, _ := math.Lgamma(float64(n + 1))
	b, _ := math.Lgamma(float64(k + 1))
	c, _ := math.Lgamma(float64(n - k + 1))
	return a - b - c
}
