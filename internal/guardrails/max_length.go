package guardrails

import (
	"fmt"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

type MaxLengthGuardrail struct {
	maxItems int
	maxChars int
}

func NewMaxLengthGuardrail(maxItems, maxChars int) *MaxLengthGuardrail {
	return &MaxLengthGuardrail{
		maxItems: maxItems,
		maxChars: maxChars,
	}
}

func (g *MaxLengthGuardrail) Name() string {
	return "max_length"
}

func (g *MaxLengthGuardrail) Supports(scope domain.Scope) bool {
	return scope == domain.ScopeRequest || scope == domain.ScopeResponse
}

func (g *MaxLengthGuardrail) Apply(payload domain.Payload) domain.Result {
	if len(payload.Texts) > g.maxItems {
		reason := fmt.Sprintf("Too many text items: %d > %d.", len(payload.Texts), g.maxItems)
		return domain.Result{
			Texts:    payload.Texts,
			Modified: false,
			Decision: domain.DecisionBlocked,
			Reason:   &reason,
		}
	}

	total := 0
	for _, text := range payload.Texts {
		total += len(text)
	}
	if total > g.maxChars {
		reason := fmt.Sprintf("Payload too large: %d > %d characters.", total, g.maxChars)
		return domain.Result{
			Texts:    payload.Texts,
			Modified: false,
			Decision: domain.DecisionBlocked,
			Reason:   &reason,
		}
	}

	return domain.Result{
		Texts:    payload.Texts,
		Modified: false,
		Decision: domain.DecisionNone,
	}
}
