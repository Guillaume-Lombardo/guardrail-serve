package guardrails

import (
	"context"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

type DetectSecretGuardrail struct {
	mask     string
	patterns []compiledPattern
}

func NewDetectSecretGuardrail(mask string, patterns []NamedPattern) (*DetectSecretGuardrail, error) {
	compiled, err := compilePatterns(patterns)
	if err != nil {
		return nil, err
	}
	return &DetectSecretGuardrail{mask: mask, patterns: compiled}, nil
}

func (g *DetectSecretGuardrail) Name() string {
	return "detect_secret"
}

func (g *DetectSecretGuardrail) Supports(scope domain.Scope) bool {
	return scope == domain.ScopeRequest || scope == domain.ScopeResponse
}

func (g *DetectSecretGuardrail) Apply(_ context.Context, payload domain.Payload) (domain.Result, error) {
	output := make([]string, 0, len(payload.Texts))
	modified := false

	for _, text := range payload.Texts {
		findings := make([]Finding, 0)
		for _, pattern := range g.patterns {
			matches := pattern.Regex.FindAllStringSubmatchIndex(text, -1)
			for _, match := range matches {
				names := pattern.Regex.SubexpNames()
				for groupIndex, name := range names {
					if name != "secret" || groupIndex == 0 {
						continue
					}
					start := match[groupIndex*2]
					end := match[groupIndex*2+1]
					if start >= 0 && end >= 0 {
						findings = append(findings, Finding{Start: start, End: end})
					}
				}
			}
		}

		findings = deduplicateFindings(findings)
		redacted, changed := redactText(text, g.mask, findings)
		output = append(output, redacted)
		modified = modified || changed
	}

	if modified {
		return domain.Result{
			Texts:    output,
			Modified: true,
			Decision: domain.DecisionGuardrailIntervened,
		}, nil
	}

	return domain.Result{
		Texts:    output,
		Modified: false,
		Decision: domain.DecisionNone,
	}, nil
}
