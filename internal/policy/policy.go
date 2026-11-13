// Package policy compiles named guardrail policies and evaluates them over
// text items. It depends only on the domain contracts: transports, resource
// loading and concrete detectors are injected.
package policy

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidName reports whether name is a syntactically valid policy name.
func ValidName(name string) bool { return namePattern.MatchString(name) }

const typePlaceholder = "{TYPE}"

const maxMaskRunes = 64

// Mask renders the replacement for a masked span.
type Mask struct {
	template string
	typed    bool
}

// LiteralMask replaces spans with value verbatim; placeholders are not expanded.
func LiteralMask(value string) Mask { return Mask{template: value} }

// ParseMaskTemplate validates a policy mask. "{TYPE}" expands to the finding type,
// for example "[{TYPE}]" renders "[EMAIL]". Any other brace is rejected so that
// misspelled placeholders fail at load time.
func ParseMaskTemplate(value string) (Mask, error) {
	if value == "" {
		return Mask{}, fmt.Errorf("mask must not be empty")
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxMaskRunes {
		return Mask{}, fmt.Errorf("mask must be valid UTF-8 of at most %d characters", maxMaskRunes)
	}
	if strings.ContainsAny(strings.ReplaceAll(value, typePlaceholder, ""), "{}") {
		return Mask{}, fmt.Errorf("mask %q: only the %s placeholder is supported", value, typePlaceholder)
	}
	return Mask{template: value, typed: strings.Contains(value, typePlaceholder)}, nil
}

func (m Mask) render(findingType string) string {
	if !m.typed {
		return m.template
	}
	return strings.ReplaceAll(m.template, typePlaceholder, findingType)
}

// Step is one detector in an ordered stage chain.
type Step struct {
	Detector domain.Detector
	Action   domain.Action
	Mask     Mask
}

// Policy is a validated, compiled policy. Stages are always both defined;
// an empty chain means only payload limits apply to that stage.
type Policy struct {
	Name   string
	Mode   domain.Mode
	stages map[domain.Stage][]Step
}

// NewPolicy validates an in-code policy (used for the fixed /scan routes).
func NewPolicy(name string, mode domain.Mode, input, output []Step) (*Policy, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid policy name %q", name)
	}
	if _, err := domain.ParseMode(string(mode)); err != nil {
		return nil, err
	}
	policy := &Policy{Name: name, Mode: mode, stages: map[domain.Stage][]Step{}}
	for _, stage := range domain.Stages() {
		steps := input
		if stage == domain.StageOutput {
			steps = output
		}
		if err := validateChain(stage, steps); err != nil {
			return nil, err
		}
		policy.stages[stage] = append([]Step(nil), steps...)
	}
	return policy, nil
}

func validateChain(stage domain.Stage, steps []Step) error {
	seen := map[string]struct{}{}
	for index, step := range steps {
		if step.Detector == nil {
			return fmt.Errorf("stage %s step %d: detector is required", stage, index)
		}
		name := step.Detector.Name()
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("stage %s step %d: duplicate detector %q", stage, index, name)
		}
		seen[name] = struct{}{}
		if _, err := domain.ParseAction(string(step.Action)); err != nil {
			return fmt.Errorf("stage %s step %d: %w", stage, index, err)
		}
		if !step.Detector.Supports(stage) {
			return fmt.Errorf("stage %s step %d: detector %q does not support stage %s", stage, index, name, stage)
		}
		if step.Action == domain.ActionMask && step.Mask.template == "" {
			return fmt.Errorf("stage %s step %d: mask action requires a mask", stage, index)
		}
	}
	return nil
}

// Catalog is an immutable set of named policies.
type Catalog struct {
	policies map[string]*Policy
	names    []string
}

func NewCatalog(policies ...*Policy) (*Catalog, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("at least one policy is required")
	}
	catalog := &Catalog{policies: make(map[string]*Policy, len(policies))}
	for _, policy := range policies {
		if _, duplicate := catalog.policies[policy.Name]; duplicate {
			return nil, fmt.Errorf("duplicate policy %q", policy.Name)
		}
		catalog.policies[policy.Name] = policy
		catalog.names = append(catalog.names, policy.Name)
	}
	return catalog, nil
}

// Get returns the named policy. There is no fallback: unknown names fail.
func (c *Catalog) Get(name string) (*Policy, bool) {
	policy, ok := c.policies[name]
	return policy, ok
}

// Names returns policy names in declaration order.
func (c *Catalog) Names() []string { return append([]string(nil), c.names...) }
