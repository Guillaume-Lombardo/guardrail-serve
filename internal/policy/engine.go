package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

// Evaluation is the outcome of one policy over one ordered list of texts.
type Evaluation struct {
	Policy string
	Mode   domain.Mode
	Stage  domain.Stage
	// Decision is the applied decision; in detect mode it is NONE unless a
	// payload limit blocked the request.
	Decision domain.Decision
	// PolicyDecision is the decision the policy produces in enforce mode.
	PolicyDecision domain.Decision
	// Texts is aligned one to one with the input texts.
	Texts []string
	// Findings are sorted by text index, start, end, chain position and rule.
	Findings []domain.Finding
	// Reason explains a BLOCKED policy decision without including text values.
	Reason *string
	// LimitExceeded reports that payload limits blocked before any detector ran.
	LimitExceeded bool
}

// Engine evaluates compiled policies. Limits are checked first for every
// stage and mode because they protect resources rather than express policy.
type Engine struct {
	limits   domain.Guardrail
	observer Observer
}

func NewEngine(limits domain.Guardrail) *Engine {
	return NewEngineWithObserver(limits, nil)
}

// NewEngineWithObserver installs an optional observer for the engine lifetime.
func NewEngineWithObserver(limits domain.Guardrail, observer Observer) *Engine {
	return &Engine{limits: limits, observer: observer}
}

// DetectorError identifies the failing detector without exposing text values.
type DetectorError struct {
	Detector string
	Err      error
}

func (e *DetectorError) Error() string { return fmt.Sprintf("detector %s: %v", e.Detector, e.Err) }

func (e *DetectorError) Unwrap() error { return e.Err }

type located struct {
	finding domain.Finding
	start   int // byte offsets in the original text
	end     int
	step    int
	mask    string
}

func (e *Engine) Evaluate(ctx context.Context, policy *Policy, stage domain.Stage, texts []string) (evaluation Evaluation, err error) {
	started := time.Now()
	defer func() {
		outcome := OutcomeClean
		if err != nil {
			outcome = OutcomeError
		} else if len(evaluation.Findings) > 0 || evaluation.LimitExceeded {
			outcome = OutcomeMatch
		}
		e.observe(Observation{Policy: policy.Name, Mode: policy.Mode, Stage: stage, Decision: evaluation.Decision, Outcome: outcome}, started)
	}()
	evaluation = Evaluation{
		Policy: policy.Name, Mode: policy.Mode, Stage: stage,
		Decision: domain.DecisionNone, PolicyDecision: domain.DecisionNone,
		Texts: texts, Findings: []domain.Finding{},
	}
	steps, ok := policy.stages[stage]
	if !ok {
		return Evaluation{}, fmt.Errorf("policy %q: unknown stage %q", policy.Name, stage)
	}
	if e.limits != nil {
		limitStart := time.Now()
		result, err := e.limits.Apply(ctx, domain.Payload{Texts: texts, Scope: scopeForStage(stage)})
		outcome := OutcomeClean
		if err != nil {
			outcome = OutcomeError
		} else if result.Decision == domain.DecisionBlocked {
			outcome = OutcomeMatch
		}
		e.observe(Observation{Policy: policy.Name, Mode: policy.Mode, Stage: stage, Detector: e.limits.Name(), Action: domain.ActionBlock, Outcome: outcome}, limitStart)
		if err != nil {
			return Evaluation{}, &DetectorError{Detector: e.limits.Name(), Err: err}
		}
		if result.Decision == domain.DecisionBlocked {
			evaluation.Decision, evaluation.PolicyDecision = domain.DecisionBlocked, domain.DecisionBlocked
			evaluation.Reason, evaluation.LimitExceeded = result.Reason, true
			return evaluation, nil
		}
	}

	perText := make([][]located, len(texts))
	var blocking *located
	masked := false
	for index, text := range texts {
		items, err := e.detect(ctx, policy, stage, steps, index, text)
		if err != nil {
			return Evaluation{}, err
		}
		perText[index] = items
		for i := range items {
			item := &items[i]
			switch item.finding.Action {
			case domain.ActionBlock:
				if blocking == nil || item.step < blocking.step {
					blocking = item
				}
			case domain.ActionMask:
				masked = true
			}
			evaluation.Findings = append(evaluation.Findings, item.finding)
		}
	}

	switch {
	case blocking != nil:
		evaluation.PolicyDecision = domain.DecisionBlocked
		reason := steps[blocking.step].Detector.BlockReason()
		evaluation.Reason = &reason
	case masked:
		evaluation.PolicyDecision = domain.DecisionGuardrailIntervened
	}
	if policy.Mode != domain.ModeEnforce {
		return evaluation, nil
	}
	evaluation.Decision = evaluation.PolicyDecision
	if evaluation.Decision == domain.DecisionGuardrailIntervened {
		output := make([]string, len(texts))
		for index, text := range texts {
			output[index] = applyMasks(text, perText[index])
		}
		evaluation.Texts = output
	}
	return evaluation, nil
}

func scopeForStage(stage domain.Stage) domain.Scope {
	if stage == domain.StageOutput {
		return domain.ScopeResponse
	}
	return domain.ScopeRequest
}

// detect runs every step on the original text; later steps never see earlier
// rewrites, so all offsets refer to the same original text.
func (e *Engine) detect(ctx context.Context, selected *Policy, stage domain.Stage, steps []Step, textIndex int, text string) ([]located, error) {
	var items []located
	var offsets *runeOffsets
	for stepIndex, step := range steps {
		started := time.Now()
		detections, err := step.Detector.Detect(ctx, text)
		if err == nil {
			for _, detection := range detections {
				if !validSpan(text, detection.Start, detection.End) {
					err = fmt.Errorf("invalid span [%d,%d)", detection.Start, detection.End)
					break
				}
			}
		}
		outcome := OutcomeClean
		if err != nil {
			outcome = OutcomeError
		} else if len(detections) > 0 {
			outcome = OutcomeMatch
		}
		e.observe(Observation{Policy: selected.Name, Mode: selected.Mode, Stage: stage, Detector: step.Detector.Name(), Action: step.Action, Outcome: outcome}, started)
		if err != nil {
			return nil, &DetectorError{Detector: step.Detector.Name(), Err: err}
		}
		for _, detection := range detections {
			if offsets == nil {
				offsets = newRuneOffsets(text)
			}
			item := located{
				finding: domain.Finding{
					TextIndex: textIndex, Detector: step.Detector.Name(), Type: detection.Type, Rule: detection.Rule,
					Start: offsets.of(detection.Start), End: offsets.of(detection.End),
					Score: detection.Score, Action: step.Action,
				},
				start: detection.Start, end: detection.End, step: stepIndex,
			}
			if step.Action == domain.ActionMask {
				item.mask = step.Mask.render(detection.Type)
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return less(items[i], items[j]) })
	return dedupe(items), nil
}

func validSpan(text string, start, end int) bool {
	return start >= 0 && start < end && end <= len(text) &&
		utf8.RuneStart(text[start]) && (end == len(text) || utf8.RuneStart(text[end]))
}

func less(a, b located) bool {
	switch {
	case a.start != b.start:
		return a.start < b.start
	case a.end != b.end:
		return a.end < b.end
	case a.step != b.step:
		return a.step < b.step
	case a.finding.Rule != b.finding.Rule:
		return a.finding.Rule < b.finding.Rule
	}
	return a.finding.Type < b.finding.Type
}

func dedupe(items []located) []located {
	output := items[:0]
	for index, item := range items {
		if index > 0 {
			previous := output[len(output)-1]
			if previous.start == item.start && previous.end == item.end && previous.step == item.step &&
				previous.finding.Rule == item.finding.Rule && previous.finding.Type == item.finding.Type {
				continue
			}
		}
		output = append(output, item)
	}
	return output
}

type maskCluster struct {
	start, end int
	label      located
}

// applyMasks replaces masked spans in the original text. Overlapping spans
// merge into one replacement; touching spans merge only when they render the
// same mask. A merged span uses the mask of its highest-priority finding:
// earliest chain step, then earliest start, then longest span, then rule.
func applyMasks(text string, items []located) string {
	var clusters []maskCluster
	for _, item := range items {
		if item.finding.Action != domain.ActionMask {
			continue
		}
		if n := len(clusters); n > 0 {
			last := &clusters[n-1]
			if item.start < last.end || (item.start == last.end && item.mask == last.label.mask) {
				last.end = max(last.end, item.end)
				if higherPriority(item, last.label) {
					last.label = item
				}
				continue
			}
		}
		clusters = append(clusters, maskCluster{start: item.start, end: item.end, label: item})
	}
	if len(clusters) == 0 {
		return text
	}
	var builder strings.Builder
	cursor := 0
	for _, cluster := range clusters {
		builder.WriteString(text[cursor:cluster.start])
		builder.WriteString(cluster.label.mask)
		cursor = cluster.end
	}
	builder.WriteString(text[cursor:])
	return builder.String()
}

func higherPriority(a, b located) bool {
	switch {
	case a.step != b.step:
		return a.step < b.step
	case a.start != b.start:
		return a.start < b.start
	case a.end-a.start != b.end-b.start:
		return a.end-a.start > b.end-b.start
	}
	return a.finding.Rule < b.finding.Rule
}

// runeOffsets projects byte offsets of the scanned text onto rune offsets of
// the original text. Today the scanned text is the original; a future
// normalization layer will compose its own offset map before this projection.
type runeOffsets struct {
	starts []int
	length int
}

func newRuneOffsets(text string) *runeOffsets {
	starts := make([]int, 0, len(text))
	for index := range text {
		starts = append(starts, index)
	}
	return &runeOffsets{starts: starts, length: len(text)}
}

func (r *runeOffsets) of(byteOffset int) int {
	if byteOffset >= r.length {
		return len(r.starts)
	}
	return sort.SearchInts(r.starts, byteOffset)
}
