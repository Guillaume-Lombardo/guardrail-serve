package guardrails

import (
	"context"
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

func (g *MaxLengthGuardrail) Apply(_ context.Context, payload domain.Payload) (domain.Result, error) {
	if len(payload.Texts) > g.maxItems {
		reason := fmt.Sprintf("Too many text items: %d > %d.", len(payload.Texts), g.maxItems)
		return domain.Result{
			Texts:    payload.Texts,
			Modified: false,
			Decision: domain.DecisionBlocked,
			Reason:   &reason,
		}, nil
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
		}, nil
	}

	return domain.Result{
		Texts:    payload.Texts,
		Modified: false,
		Decision: domain.DecisionNone,
	}, nil
}
