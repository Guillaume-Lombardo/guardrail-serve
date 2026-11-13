package eval

// Confusion counts the outcomes of one detector over labelled cases.
// "Positive" means the detector is expected to detect (or did detect) the case.
type Confusion struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	TN int `json:"tn"`
	FN int `json:"fn"`
}

// Add records one evaluated case.
func (c *Confusion) Add(expected, detected bool) {
	switch {
	case expected && detected:
		c.TP++
	case !expected && detected:
		c.FP++
	case !expected && !detected:
		c.TN++
	default:
		c.FN++
	}
}

// Merge adds another confusion matrix (micro aggregation).
func (c *Confusion) Merge(other Confusion) {
	c.TP += other.TP
	c.FP += other.FP
	c.TN += other.TN
	c.FN += other.FN
}

// Total is the number of evaluated cases.
func (c Confusion) Total() int { return c.TP + c.FP + c.TN + c.FN }

// Ratio is a metric with an explicit zero-denominator rule.
//
// When the denominator is zero the ratio is not computable: Defined is false
// and Value is 0. It is never NaN, so reports always encode as valid JSON.
type Ratio struct {
	Value   float64 `json:"value"`
	Defined bool    `json:"defined"`
}

func ratio(numerator, denominator int) Ratio {
	if denominator == 0 {
		return Ratio{}
	}
	return Ratio{Value: float64(numerator) / float64(denominator), Defined: true}
}

// Metrics derives precision, recall and false positive rate.
//
//	precision = TP / (TP + FP)   undefined without any detection
//	recall    = TP / (TP + FN)   undefined without any expected positive
//	fpr       = FP / (FP + TN)   undefined without any expected negative
type Metrics struct {
	Precision Ratio `json:"precision"`
	Recall    Ratio `json:"recall"`
	FPR       Ratio `json:"fpr"`
}

// Metrics computes the derived ratios.
func (c Confusion) Metrics() Metrics {
	return Metrics{
		Precision: ratio(c.TP, c.TP+c.FP),
		Recall:    ratio(c.TP, c.TP+c.FN),
		FPR:       ratio(c.FP, c.FP+c.TN),
	}
}

// macro averages each ratio over the detectors for which it is defined.
func macro(all []Metrics) Metrics {
	mean := func(pick func(Metrics) Ratio) Ratio {
		sum, count := 0.0, 0
		for _, m := range all {
			if r := pick(m); r.Defined {
				sum += r.Value
				count++
			}
		}
		if count == 0 {
			return Ratio{}
		}
		return Ratio{Value: sum / float64(count), Defined: true}
	}
	return Metrics{
		Precision: mean(func(m Metrics) Ratio { return m.Precision }),
		Recall:    mean(func(m Metrics) Ratio { return m.Recall }),
		FPR:       mean(func(m Metrics) Ratio { return m.FPR }),
	}
}
