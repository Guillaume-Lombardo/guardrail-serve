package guardrails

import (
	"context"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

type PromptInjectionGuardrail struct {
	patterns []compiledPattern
}

func NewPromptInjectionGuardrail(patterns []NamedPattern) (*PromptInjectionGuardrail, error) {
	compiled, err := compilePatterns(patterns)
	if err != nil {
		return nil, err
	}
	return &PromptInjectionGuardrail{patterns: compiled}, nil
}

func (g *PromptInjectionGuardrail) Name() string {
	return "prompt_injection"
}

func (g *PromptInjectionGuardrail) Supports(scope domain.Scope) bool {
	return scope == domain.ScopeRequest
}

func (g *PromptInjectionGuardrail) Apply(_ context.Context, payload domain.Payload) (domain.Result, error) {
	matchedRules := make([]string, 0)
	seen := map[string]struct{}{}

	for _, text := range payload.Texts {
		for _, pattern := range g.patterns {
			if pattern.Regex.MatchString(text) {
				if _, ok := seen[pattern.Name]; !ok {
					seen[pattern.Name] = struct{}{}
					matchedRules = append(matchedRules, pattern.Name)
				}
			}
		}
	}

	if len(matchedRules) > 0 {
		return domain.Result{
			Texts:    payload.Texts,
			Modified: false,
			Decision: domain.DecisionBlocked,
			Reason:   stringPtr("Potential prompt injection detected."),
			Metadata: map[string]any{"matched_rules": matchedRules},
		}, nil
	}

	return domain.Result{
		Texts:    payload.Texts,
		Modified: false,
		Decision: domain.DecisionNone,
		Metadata: map[string]any{"matched_rules": []string{}},
	}, nil
}
