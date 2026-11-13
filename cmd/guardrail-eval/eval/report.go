package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// ReportVersion is the version of the JSON report contract.
const ReportVersion = 1

// maxErrorSamples bounds the failures listed individually in a report.
const maxErrorSamples = 20

// Format selects the report encoding.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// ParseFormat validates an output format; empty means text.
func ParseFormat(value string) (Format, error) {
	switch Format(value) {
	case "", FormatText:
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	}
	return "", fmt.Errorf("format must be %q or %q, got %q", FormatText, FormatJSON, value)
}

// Target describes what was evaluated. It never holds credentials.
type Target struct {
	BaseURL string `json:"base_url"`
	Mode    Mode   `json:"mode"`
	// Policy is set in annotate mode only.
	Policy string `json:"policy,omitempty"`
}

// CorpusInfo identifies an evaluated corpus.
type CorpusInfo struct {
	Name           string  `json:"name"`
	Description    string  `json:"description,omitempty"`
	License        string  `json:"license,omitempty"`
	LabelSemantics string  `json:"label_semantics,omitempty"`
	Source         *Source `json:"source,omitempty"`
	Cases          int     `json:"cases"`
	SHA256         string  `json:"sha256"`
	// Detectors and Aggregate are scoped to this corpus alone: corpora carry
	// their own label semantics and are never pooled.
	Detectors map[string]DetectorReport `json:"detectors"`
	Aggregate Aggregate                 `json:"aggregate"`
}

// RunSummary counts the work done.
type RunSummary struct {
	Cases        int `json:"cases"`
	CasesErrored int `json:"cases_errored"`
	Requests     int `json:"requests"`
}

// GroupResult is a confusion matrix with its derived metrics.
type GroupResult struct {
	Counts  Confusion `json:"counts"`
	Metrics Metrics   `json:"metrics"`
}

func group(c Confusion) GroupResult { return GroupResult{Counts: c, Metrics: c.Metrics()} }

// DetectorReport holds one detector's totals and breakdowns.
type DetectorReport struct {
	GroupResult
	// Errored counts labelled evaluations excluded because the request failed.
	Errored    int                    `json:"errored"`
	ByLanguage map[string]GroupResult `json:"by_language"`
	ByTag      map[string]GroupResult `json:"by_tag"`
}

// Aggregate combines detectors. Micro sums the confusion matrices; Macro
// averages each metric over the detectors where it is defined.
type Aggregate struct {
	Micro GroupResult `json:"micro"`
	Macro Metrics     `json:"macro"`
}

// ErrorSample is one failed request.
type ErrorSample struct {
	Corpus   string    `json:"corpus"`
	CaseID   string    `json:"case_id"`
	Detector string    `json:"detector,omitempty"`
	Kind     ErrorKind `json:"kind"`
	Status   int       `json:"status,omitempty"`
	Message  string    `json:"message"`
}

// ErrorSummary reports failed requests, which are never detection outcomes.
type ErrorSummary struct {
	Total   int            `json:"total"`
	ByKind  map[string]int `json:"by_kind"`
	Samples []ErrorSample  `json:"samples"`
	// Truncated is true when Samples omits some failures.
	Truncated bool `json:"truncated"`
}

// Report is the machine-readable evaluation report (version 1). It contains
// no timestamps or durations, so equal inputs give equal reports.
type Report struct {
	ReportVersion int          `json:"report_version"`
	Status        Status       `json:"status"`
	AbortReason   string       `json:"abort_reason,omitempty"`
	Target        Target       `json:"target"`
	Corpora       []CorpusInfo `json:"corpora"`
	Run           RunSummary   `json:"run"`
	Errors        ErrorSummary `json:"errors"`
	Warnings      []string     `json:"warnings"`
}

// BuildReport turns a raw result into a report.
func BuildReport(result *Result, target Target, corpora []*Corpus) *Report {
	report := &Report{
		ReportVersion: ReportVersion,
		Status:        result.Status,
		AbortReason:   result.AbortReason,
		Target:        target,
		Corpora:       make([]CorpusInfo, 0, len(corpora)),
		Run:           RunSummary{Cases: result.Cases, CasesErrored: result.CasesErrored, Requests: result.Requests},
		Warnings:      []string{},
		Errors:        ErrorSummary{ByKind: map[string]int{}, Samples: []ErrorSample{}},
	}
	for index, corpus := range corpora {
		h := corpus.Header
		info := CorpusInfo{
			Name: h.Name, Description: h.Description, License: h.License, LabelSemantics: h.LabelSemantics,
			Source: h.Source, Cases: len(corpus.Cases), SHA256: corpus.SHA256,
			Detectors: map[string]DetectorReport{},
		}
		var micro Confusion
		var perDetector []Metrics
		tallies := result.Corpora[index].Detectors
		for _, name := range sortedKeys(tallies) {
			t := tallies[name]
			entry := DetectorReport{
				GroupResult: group(t.total), Errored: t.errored,
				ByLanguage: groups(t.byLang), ByTag: groups(t.byTag),
			}
			info.Detectors[name] = entry
			micro.Merge(t.total)
			perDetector = append(perDetector, entry.Metrics)
			if target.Mode == ModeAnnotate && t.total.TP+t.total.FN > 0 && t.total.TP+t.total.FP == 0 {
				report.Warnings = append(report.Warnings, fmt.Sprintf(
					"corpus %q: detector %q reported no finding for any case; check that policy %q runs it on the evaluated stage", h.Name, name, target.Policy))
			}
		}
		info.Aggregate = Aggregate{Micro: group(micro), Macro: macro(perDetector)}
		report.Corpora = append(report.Corpora, info)
	}

	for _, failure := range result.Failures {
		report.Errors.Total++
		report.Errors.ByKind[string(failure.Kind)]++
		if len(report.Errors.Samples) < maxErrorSamples {
			report.Errors.Samples = append(report.Errors.Samples, ErrorSample(failure))
		}
	}
	report.Errors.Truncated = report.Errors.Total > len(report.Errors.Samples)
	return report
}

func groups(source map[string]*Confusion) map[string]GroupResult {
	out := make(map[string]GroupResult, len(source))
	for key, c := range source {
		out[key] = group(*c)
	}
	return out
}

// WriteJSON writes the report as indented JSON with a trailing newline.
func (r *Report) WriteJSON(writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(r)
}

// WriteText writes a human-readable summary.
func (r *Report) WriteText(writer io.Writer) error {
	var out strings.Builder
	fmt.Fprintf(&out, "guardrail-eval report v%d\n", r.ReportVersion)
	fmt.Fprintf(&out, "status:  %s", r.Status)
	if r.AbortReason != "" {
		fmt.Fprintf(&out, " (%s)", r.AbortReason)
	}
	fmt.Fprintf(&out, "\ntarget:  %s mode=%s", r.Target.BaseURL, r.Target.Mode)
	if r.Target.Policy != "" {
		fmt.Fprintf(&out, " policy=%s", r.Target.Policy)
	}
	fmt.Fprintf(&out, "\nrun:     %d cases, %d requests, %d cases with request errors\n", r.Run.Cases, r.Run.Requests, r.Run.CasesErrored)
	for _, corpus := range r.Corpora {
		fmt.Fprintf(&out, "corpus:  %s (%d cases, sha256 %.12s)\n", corpus.Name, corpus.Cases, corpus.SHA256)
	}
	for _, corpus := range r.Corpora {
		if err := writeCorpusText(&out, corpus); err != nil {
			return err
		}
	}
	out.WriteString("\nPer-tag breakdowns are in the JSON report (--format json). Corpora are reported separately: their labels are not comparable.\n")

	if r.Errors.Total > 0 {
		fmt.Fprintf(&out, "\nRequest errors (not detection outcomes): %d\n", r.Errors.Total)
		for _, kind := range sortedKeys(r.Errors.ByKind) {
			fmt.Fprintf(&out, "  %s: %d\n", kind, r.Errors.ByKind[kind])
		}
		for _, sample := range r.Errors.Samples {
			fmt.Fprintf(&out, "  - %s/%s", sample.Corpus, sample.CaseID)
			if sample.Detector != "" {
				fmt.Fprintf(&out, " [%s]", sample.Detector)
			}
			fmt.Fprintf(&out, ": %s\n", sample.Message)
		}
		if r.Errors.Truncated {
			fmt.Fprintf(&out, "  ... %d more not listed\n", r.Errors.Total-len(r.Errors.Samples))
		}
	}
	for _, warning := range r.Warnings {
		fmt.Fprintf(&out, "warning: %s\n", warning)
	}
	_, err := io.WriteString(writer, out.String())
	return err
}

func writeHeader(w io.Writer, first string) {
	fmt.Fprintf(w, "%s\tTP\tFP\tTN\tFN\tprecision\trecall\tfpr\terrored\n", first)
}

func writeRow(w io.Writer, name string, g GroupResult, errored string) {
	fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\n", name,
		g.Counts.TP, g.Counts.FP, g.Counts.TN, g.Counts.FN,
		format(g.Metrics.Precision), format(g.Metrics.Recall), format(g.Metrics.FPR), errored)
}

func writeMetricsOnly(w io.Writer, name string, m Metrics) {
	fmt.Fprintf(w, "%s\t-\t-\t-\t-\t%s\t%s\t%s\t-\n", name, format(m.Precision), format(m.Recall), format(m.FPR))
}

func format(r Ratio) string {
	if !r.Defined {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", r.Value)
}

func writeCorpusText(out *strings.Builder, corpus CorpusInfo) error {
	fmt.Fprintf(out, "\n== %s ==\nTotals (precision, recall, fpr show n/a when the denominator is zero)\n", corpus.Name)
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	writeHeader(table, "detector")
	names := sortedKeys(corpus.Detectors)
	for _, name := range names {
		entry := corpus.Detectors[name]
		writeRow(table, name, entry.GroupResult, fmt.Sprint(entry.Errored))
	}
	writeRow(table, "micro", corpus.Aggregate.Micro, "-")
	writeMetricsOnly(table, "macro", corpus.Aggregate.Macro)
	if err := table.Flush(); err != nil {
		return err
	}

	table = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	rows := 0
	for _, name := range names {
		entries := corpus.Detectors[name].ByLanguage
		for _, key := range sortedKeys(entries) {
			if rows == 0 {
				out.WriteString("\nBy language\n")
				writeHeader(table, "detector/language")
			}
			rows++
			writeRow(table, name+"/"+key, entries[key], "-")
		}
	}
	return table.Flush()
}
