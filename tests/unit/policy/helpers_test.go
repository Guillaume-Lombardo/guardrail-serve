package policy_test

import (
	"context"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
	"github.com/g1lom/guardrail-serve/internal/policy"
)

// Fixed fixtures: emails (PII), "pw=<value>" secrets and "ignore rules" injections.
func fixtureDetectors(t *testing.T) (secret, pii, prompt domain.Detector) {
	t.Helper()
	s, err := guardrails.NewSecretDetector([]guardrails.NamedPattern{
		{Name: "pw", Type: "PASSWORD", Regex: `pw=(?P<secret>[^\s]+)`},
		{Name: "long", Regex: `(?P<secret>[a-z0-9@.]{20,})`},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := guardrails.NewPIIDetector([]guardrails.NamedPattern{
		{Name: "email", Type: "EMAIL", Regex: `(?P<secret>[a-z0-9.]+@[a-z0-9.]+\.[a-z]{2,})`},
	})
	if err != nil {
		t.Fatal(err)
	}
	pi, err := guardrails.NewPromptInjectionDetector([]guardrails.NamedPattern{
		{Name: "ignore_rules", Regex: `(?i)ignore (all )?rules`},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, p, pi
}

func detectorMap(detectors ...domain.Detector) map[string]domain.Detector {
	output := map[string]domain.Detector{}
	for _, detector := range detectors {
		output[detector.Name()] = detector
	}
	return output
}

func mustMask(t *testing.T, template string) policy.Mask {
	t.Helper()
	mask, err := policy.ParseMaskTemplate(template)
	if err != nil {
		t.Fatal(err)
	}
	return mask
}

func mustPolicy(t *testing.T, name string, mode domain.Mode, input, output []policy.Step) *policy.Policy {
	t.Helper()
	p, err := policy.NewPolicy(name, mode, input, output)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// staticDetector returns fixed byte spans, to exercise engine edge cases.
type staticDetector struct {
	name       string
	detections []domain.Detection
	err        error
}

func (d staticDetector) Name() string               { return d.name }
func (d staticDetector) Supports(domain.Stage) bool { return true }
func (d staticDetector) BlockReason() string        { return d.name + " blocked." }
func (d staticDetector) Detect(context.Context, string) ([]domain.Detection, error) {
	return d.detections, d.err
}
