package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
	"github.com/g1lom/guardrail-serve/internal/policy"
	"github.com/g1lom/guardrail-serve/internal/resources"
	"github.com/g1lom/guardrail-serve/internal/semantic"
	"github.com/g1lom/guardrail-serve/internal/semantic/systemone"
)

// judgeMask is the typed mask of values hidden from the System One judge.
const judgeMask = "[{TYPE}]"

// judgeOnlyPatterns widen masking for the judge without changing detect_pii:
// the user-facing email rule is ASCII-only and would leave the non-ASCII part
// of a local part (for example "jérô" in "jérôme.dupont@...") unmasked.
var judgeOnlyPatterns = []guardrails.NamedPattern{{
	Name:  "email-unicode",
	Type:  "EMAIL",
	Regex: `(?P<secret>[\p{L}\p{M}\p{N}._%+\-]+@[\p{L}\p{M}\p{N}\-]+(?:\.[\p{L}\p{M}\p{N}\-]+)*\.\p{L}{2,})`,
}}

// semanticDetector composes the optional semantic_prompt_injection detector:
// the HTTP classifier alone, the System One judge alone, or the cascade. It
// returns nil when neither is enabled. No network call is made here.
func semanticDetector(cfg config.Config, logger *slog.Logger, secret, pii domain.Detector, observer systemone.Observer) (domain.Detector, error) {
	classifier, err := cfg.Semantic.NewClassifier()
	if err != nil {
		return nil, fmt.Errorf("semantic detector configuration: %w", err)
	}
	resolved, err := cfg.SystemOne.Resolve(classifier != nil)
	if err != nil {
		return nil, fmt.Errorf("systemone judge configuration: %w", err)
	}
	var detector semantic.PromptInjectionDetector
	if classifier != nil {
		detector = classifier
	}
	if resolved != nil {
		masker, err := newJudgeMasker(cfg.GuardrailsConfigDir, secret, pii)
		if err != nil {
			return nil, fmt.Errorf("systemone judge masking: %w", err)
		}
		judge, err := systemone.NewJudge(resolved.Judge, masker, observer)
		if err != nil {
			return nil, err
		}
		detector = judge
		if resolved.Mode == systemone.ModeCascade {
			if detector, err = systemone.NewCascade(classifier, judge, resolved.Zone, observer); err != nil {
				return nil, err
			}
		}
	}
	if detector == nil {
		return nil, nil
	}
	return guardrails.NewSemanticPolicyDetector(detector, logger)
}

// judgeMasker evaluates an internal, non-recursive masking policy with its own
// engine: no payload limits, no observer, no user catalog entry. It only ever
// contains secret and PII detectors, so the judge can never be re-entered.
type judgeMasker struct {
	engine *policy.Engine
	policy *policy.Policy
}

// newJudgeMasker always includes the embedded default secret and PII detectors,
// so an operator override can add masking coverage but never remove it. The
// operator detectors are added under distinct names when an override directory
// is configured.
func newJudgeMasker(overrideDir string, secret, pii domain.Detector) (*judgeMasker, error) {
	defaultSecret, err := guardrails.NewSecretDetector(nil)
	if err != nil {
		return nil, err
	}
	defaultPIIPatterns, err := resources.LoadPatterns("", "detect_pii_patterns.yaml")
	if err != nil {
		return nil, err
	}
	defaultPII, err := guardrails.NewPIIDetector(defaultPIIPatterns)
	if err != nil {
		return nil, err
	}
	extraPII, err := guardrails.NewPIIDetector(judgeOnlyPatterns)
	if err != nil {
		return nil, err
	}
	mask, err := policy.ParseMaskTemplate(judgeMask)
	if err != nil {
		return nil, err
	}
	detectors := []domain.Detector{defaultSecret, defaultPII, renamedDetector{Detector: extraPII, name: "judge_detect_pii"}}
	if overrideDir != "" {
		detectors = append(detectors,
			renamedDetector{Detector: secret, name: "operator_detect_secret"},
			renamedDetector{Detector: pii, name: "operator_detect_pii"})
	}
	steps := make([]policy.Step, 0, len(detectors))
	for _, detector := range detectors {
		steps = append(steps, policy.Step{Detector: detector, Action: domain.ActionMask, Mask: mask})
	}
	internal, err := policy.NewPolicy("systemone-judge-masking", domain.ModeEnforce, steps, steps)
	if err != nil {
		return nil, err
	}
	return &judgeMasker{engine: policy.NewEngine(nil), policy: internal}, nil
}

func (m *judgeMasker) Mask(ctx context.Context, text string) (string, error) {
	evaluation, err := m.engine.Evaluate(ctx, m.policy, domain.StageInput, []string{text})
	if err != nil {
		return "", err
	}
	if len(evaluation.Texts) != 1 {
		return "", errors.New("masking returned an unexpected number of texts")
	}
	return evaluation.Texts[0], nil
}

// renamedDetector gives an operator detector a distinct name inside the
// internal masking policy, whose chains reject duplicate names.
type renamedDetector struct {
	domain.Detector
	name string
}

func (d renamedDetector) Name() string { return d.name }

// observerSlot forwards to metrics that are created after the detectors (their
// label allowlists need the policy catalog). The target is set once, before the
// handler is returned, so no request can observe a nil target.
type observerSlot struct{ target systemone.Observer }

func (s *observerSlot) ObserveJudgment(j systemone.Judgment) {
	if s.target != nil {
		s.target.ObserveJudgment(j)
	}
}

func (s *observerSlot) ObserveRoute(r systemone.Route) {
	if s.target != nil {
		s.target.ObserveRoute(r)
	}
}
