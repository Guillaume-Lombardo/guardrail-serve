// Package gate compares HTTP evaluation observations without pooling corpora.
package gate

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

// Snapshot is a text-free, credential-free baseline/report for one corpus.
// Groups are keyed by detector then language, with "all" for detector totals.
type Snapshot struct {
	Version       int                                    `json:"version"`
	Corpus        string                                 `json:"corpus"`
	SHA256        string                                 `json:"sha256"`
	Mode          eval.Mode                              `json:"mode"`
	Policy        string                                 `json:"policy"`
	Outcomes      map[string]map[string]bool             `json:"outcomes"`
	Groups        map[string]map[string]eval.GroupResult `json:"groups"`
	KnownFailures []Failure                              `json:"known_failures"`
}

// Failure identifies a misclassified label, never its input text.
type Failure struct {
	CaseID   string `json:"case_id"`
	Detector string `json:"detector"`
	Kind     string `json:"kind"`
}

// Measure uses the same runner as the CLI, through the public HTTP API only.
// Single-case runs retain case identity without changing report v1.
func Measure(ctx context.Context, client *eval.Client, corpus *eval.Corpus) (*Snapshot, error) {
	s := &Snapshot{Version: 1, Corpus: corpus.Header.Name, SHA256: corpus.SHA256, Mode: eval.ModeAnnotate, Policy: "audit", Outcomes: map[string]map[string]bool{}}
	for _, item := range corpus.Cases {
		one := &eval.Corpus{Header: corpus.Header, SHA256: corpus.SHA256, Cases: []eval.Case{item}}
		result, err := eval.Run(ctx, client, eval.RunConfig{Mode: s.Mode, Policy: s.Policy, MaxConsecutiveErrors: 1}, []*eval.Corpus{one})
		if err != nil {
			return nil, err
		}
		report := eval.BuildReport(result, eval.Target{Mode: s.Mode, Policy: s.Policy}, []*eval.Corpus{one})
		if report.Status != eval.StatusComplete || report.Errors.Total != 0 {
			return nil, fmt.Errorf("evaluation request failed for case %s (no detection outcome)", item.ID)
		}
		s.Outcomes[item.ID] = map[string]bool{}
		for detector := range item.Labels {
			counts := report.Corpora[0].Detectors[detector].Counts
			if counts.Total() != 1 {
				return nil, fmt.Errorf("missing observation: %s/%s", item.ID, detector)
			}
			s.Outcomes[item.ID][detector] = counts.TP+counts.FP == 1
		}
	}
	groups, failures, err := summarize(s, corpus)
	if err != nil {
		return nil, err
	}
	s.Groups, s.KnownFailures = groups, failures
	return s, nil
}

func summarize(s *Snapshot, corpus *eval.Corpus) (map[string]map[string]eval.GroupResult, []Failure, error) {
	if s.Version != 1 || s.Corpus != corpus.Header.Name || s.SHA256 != corpus.SHA256 || s.Mode != eval.ModeAnnotate || s.Policy != "audit" || len(s.Outcomes) != len(corpus.Cases) {
		return nil, nil, fmt.Errorf("snapshot identity or coverage mismatch")
	}
	groups := map[string]map[string]eval.GroupResult{}
	failures := []Failure{}
	for _, item := range corpus.Cases {
		outcomes, ok := s.Outcomes[item.ID]
		if !ok || len(outcomes) != len(item.Labels) {
			return nil, nil, fmt.Errorf("case coverage mismatch: %s", item.ID)
		}
		for detector, expected := range item.Labels {
			detected, ok := outcomes[detector]
			if !ok {
				return nil, nil, fmt.Errorf("label coverage mismatch: %s/%s", item.ID, detector)
			}
			if groups[detector] == nil {
				groups[detector] = map[string]eval.GroupResult{}
			}
			for _, lang := range []string{"all", item.Lang} {
				g := groups[detector][lang]
				g.Counts.Add(expected, detected)
				g.Metrics = g.Counts.Metrics()
				groups[detector][lang] = g
			}
			if expected != detected {
				kind := "fp"
				if expected {
					kind = "fn"
				}
				failures = append(failures, Failure{item.ID, detector, kind})
			}
		}
	}
	sort.Slice(failures, func(i, j int) bool {
		if failures[i].CaseID != failures[j].CaseID {
			return failures[i].CaseID < failures[j].CaseID
		}
		return failures[i].Detector < failures[j].Detector
	})
	return groups, failures, nil
}

// Compare rejects missing/changed fixtures, corrupt summaries and regressions.
// Thresholds are the measured baseline: precision/recall >= baseline, FPR <=
// baseline. Previously correct cases must remain correct, even if another
// improvement would compensate in every aggregate.
func Compare(baseline, current *Snapshot, corpus *eval.Corpus) []string {
	violations := []string{}
	for _, entry := range []struct {
		name     string
		snapshot *Snapshot
	}{{"baseline", baseline}, {"current", current}} {
		groups, failures, err := summarize(entry.snapshot, corpus)
		if err != nil {
			return []string{entry.name + ": " + err.Error()}
		}
		if !reflect.DeepEqual(groups, entry.snapshot.Groups) || !reflect.DeepEqual(failures, entry.snapshot.KnownFailures) {
			return []string{entry.name + ": inconsistent summary"}
		}
	}
	for _, item := range corpus.Cases {
		for detector, expected := range item.Labels {
			if baseline.Outcomes[item.ID][detector] == expected && current.Outcomes[item.ID][detector] != expected {
				violations = append(violations, "previously correct case regressed: "+item.ID+"/"+detector)
			}
		}
	}
	for detector, langs := range baseline.Groups {
		for lang, before := range langs {
			after := current.Groups[detector][lang]
			for _, metric := range []struct {
				name          string
				before, after eval.Ratio
				upper         bool
			}{
				{"precision", before.Metrics.Precision, after.Metrics.Precision, false},
				{"recall", before.Metrics.Recall, after.Metrics.Recall, false},
				{"fpr", before.Metrics.FPR, after.Metrics.FPR, true},
			} {
				// Undefined baselines impose no numeric bound. Defined metrics must
				// remain defined; undefined current precision cannot hide lost TPs.
				if metric.before.Defined && (!metric.after.Defined || (!metric.upper && metric.after.Value < metric.before.Value) || (metric.upper && metric.after.Value > metric.before.Value)) {
					violations = append(violations, "threshold regressed: "+detector+"/"+lang+"/"+metric.name)
				}
			}
		}
	}
	sort.Strings(violations)
	return violations
}
