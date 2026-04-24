package guardrails

import (
	"context"
	"errors"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/semantic"
)

type SemanticPromptInjectionGuardrail struct {
	threshold float64
	detector  semantic.PromptInjectionDetector
}

func NewSemanticPromptInjectionGuardrail(
	threshold float64,
	detector semantic.PromptInjectionDetector,
) (*SemanticPromptInjectionGuardrail, error) {
	if detector == nil {
		return nil, errors.New("semantic prompt injection detector is required")
	}
	if threshold <= 0 || threshold > 1 {
		return nil, errors.New("semantic prompt injection threshold must be in (0, 1]")
	}

	return &SemanticPromptInjectionGuardrail{
		threshold: threshold,
		detector:  detector,
	}, nil
}

func (g *SemanticPromptInjectionGuardrail) Name() string {
	return "semantic_prompt_injection"
}

func (g *SemanticPromptInjectionGuardrail) Supports(scope domain.Scope) bool {
	return scope == domain.ScopeRequest
}

func (g *SemanticPromptInjectionGuardrail) Apply(ctx context.Context, payload domain.Payload) (domain.Result, error) {
	assessment, err := g.detector.DetectPromptInjection(ctx, payload.Texts)
	if err != nil {
		return domain.Result{}, err
	}

	metadata := map[string]any{
		"semantic_score": assessment.Score,
	}
	if assessment.Model != "" {
		metadata["semantic_model"] = assessment.Model
	}
	for key, value := range assessment.Metadata {
		metadata[key] = value
	}

	if assessment.Triggered || assessment.Score >= g.threshold {
		reason := assessment.Reason
		if reason == "" {
			reason = "Potential prompt injection detected."
		}
		return domain.Result{
			Texts:    payload.Texts,
			Modified: false,
			Decision: domain.DecisionBlocked,
			Reason:   stringPtr(reason),
			Metadata: metadata,
		}, nil
	}

	return domain.Result{
		Texts:    payload.Texts,
		Modified: false,
		Decision: domain.DecisionNone,
		Metadata: metadata,
	}, nil
}
