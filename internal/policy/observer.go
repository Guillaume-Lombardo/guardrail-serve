package policy

import (
	"time"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

// Observation describes one completed policy evaluation or detector invocation.
// Detector is empty for policy evaluations. No input, findings or error text is carried.
// Detector calls count per text; payload limits count once per evaluation.
type Observation struct {
	Policy   string
	Mode     domain.Mode
	Stage    domain.Stage
	Detector string
	Action   domain.Action
	Decision domain.Decision
	Outcome  Outcome
	Duration time.Duration
}

type Outcome string

const (
	OutcomeClean Outcome = "clean"
	OutcomeMatch Outcome = "match"
	OutcomeError Outcome = "error"
)

// Observer must be concurrency safe and return promptly. Called synchronously;
// implementations must not panic or alter evaluation behavior.
type Observer interface{ Observe(Observation) }

func (e *Engine) observe(o Observation, started time.Time) {
	if e.observer != nil {
		o.Duration = time.Since(started)
		e.observer.Observe(o)
	}
}
