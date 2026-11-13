package policy_test

import (
	"context"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
	"github.com/g1lom/guardrail-serve/internal/policy"
)

type observationLog []policy.Observation

func (l *observationLog) Observe(o policy.Observation) { *l = append(*l, o) }

type cleanObservedDetector struct{}

func (cleanObservedDetector) Name() string               { return "clean" }
func (cleanObservedDetector) Supports(domain.Stage) bool { return true }
func (cleanObservedDetector) BlockReason() string        { return "blocked" }
func (cleanObservedDetector) Detect(context.Context, string) ([]domain.Detection, error) {
	return nil, nil
}
func TestObserverCountsActualCleanCallsAndLimitShortCircuit(t *testing.T) {
	p, err := policy.NewPolicy("observed", domain.ModeEnforce, []policy.Step{{Detector: cleanObservedDetector{}, Action: domain.ActionAnnotate}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var log observationLog
	engine := policy.NewEngineWithObserver(guardrails.NewMaxLengthGuardrail(2, 100), &log)
	if _, err := engine.Evaluate(context.Background(), p, domain.StageInput, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	if len(log) != 4 {
		t.Fatalf("observations = %v", log)
	}
	for _, o := range log {
		if o.Outcome != policy.OutcomeClean || o.Duration < 0 {
			t.Fatalf("unexpected observation: %+v", o)
		}
	}
	if log[0].Detector != "max_length" || log[1].Detector != "clean" || log[2].Detector != "clean" || log[3].Detector != "" || log[3].Decision != domain.DecisionNone {
		t.Fatal(log)
	}
	log = nil
	result, err := engine.Evaluate(context.Background(), p, domain.StageInput, []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.LimitExceeded || len(log) != 2 || log[0].Detector != "max_length" || log[1].Detector != "" || log[1].Decision != domain.DecisionBlocked {
		t.Fatal(log)
	}
	for _, o := range log {
		if o.Outcome != policy.OutcomeMatch {
			t.Fatal(log)
		}
	}
}
