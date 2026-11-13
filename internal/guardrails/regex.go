package guardrails

import (
	"context"
	"fmt"
	"regexp"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

// NamedPattern is one YAML rule. Type labels findings (and typed masks); when
// empty, the detector's default type applies.
type NamedPattern struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	Regex string `yaml:"regex"`
}

var findingTypePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// spanSelector chooses the reported span inside one regex match.
type spanSelector int

const (
	// spanSecretGroup reports every non-empty capture group named "secret".
	spanSecretGroup spanSelector = iota
	// spanWholeMatch reports the whole non-empty match.
	spanWholeMatch
)

type compiledRule struct {
	name    string
	kind    string
	regex   *regexp.Regexp
	secrets []int
}

// RegexDetector is the shared mechanism behind the deterministic detectors.
// Each built-in detector only declares its name, default type, span selection
// and block reason.
type RegexDetector struct {
	name        string
	blockReason string
	rules       []compiledRule
}

func newRegexDetector(name, defaultType, blockReason string, selector spanSelector, patterns []NamedPattern) (*RegexDetector, error) {
	rules := make([]compiledRule, 0, len(patterns))
	for index, pattern := range patterns {
		if pattern.Regex == "" {
			return nil, fmt.Errorf("%s pattern %d (%q): regex is required", name, index, pattern.Name)
		}
		re, err := regexp.Compile(pattern.Regex)
		if err != nil {
			return nil, fmt.Errorf("%s pattern %d (%q): %w", name, index, pattern.Name, err)
		}
		kind := pattern.Type
		if kind == "" {
			kind = defaultType
		}
		if !findingTypePattern.MatchString(kind) {
			return nil, fmt.Errorf("%s pattern %d (%q): type %q must match %s", name, index, pattern.Name, kind, findingTypePattern)
		}
		rule := compiledRule{name: pattern.Name, kind: kind, regex: re}
		if selector == spanSecretGroup {
			for group, groupName := range re.SubexpNames() {
				if group > 0 && groupName == "secret" {
					rule.secrets = append(rule.secrets, group)
				}
			}
			if len(rule.secrets) == 0 {
				return nil, fmt.Errorf("%s pattern %d (%q): a (?P<secret>...) group is required", name, index, pattern.Name)
			}
		}
		rules = append(rules, rule)
	}
	return &RegexDetector{name: name, blockReason: blockReason, rules: rules}, nil
}

// NewSecretDetector builds the contextual secret detector (detect_secret).
func NewSecretDetector(patterns []NamedPattern) (*RegexDetector, error) {
	return newRegexDetector("detect_secret", "SECRET", "Secret detected.", spanSecretGroup, patterns)
}

// NewPIIDetector builds the personal data detector (detect_pii).
func NewPIIDetector(patterns []NamedPattern) (*RegexDetector, error) {
	return newRegexDetector("detect_pii", "PII", "Personal data detected.", spanSecretGroup, patterns)
}

// NewPromptInjectionDetector builds the deterministic prompt-injection detector.
func NewPromptInjectionDetector(patterns []NamedPattern) (*RegexDetector, error) {
	return newRegexDetector("prompt_injection", "PROMPT_INJECTION", "Potential prompt injection detected.", spanWholeMatch, patterns)
}

func (d *RegexDetector) Name() string { return d.name }

func (d *RegexDetector) BlockReason() string { return d.blockReason }

func (d *RegexDetector) Supports(stage domain.Stage) bool {
	return stage == domain.StageInput || stage == domain.StageOutput
}

// Rules returns rule names in configuration order.
func (d *RegexDetector) Rules() []string {
	names := make([]string, len(d.rules))
	for i, rule := range d.rules {
		names[i] = rule.name
	}
	return names
}

func (d *RegexDetector) Detect(ctx context.Context, text string) ([]domain.Detection, error) {
	var detections []domain.Detection
	for _, rule := range d.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, match := range rule.regex.FindAllStringSubmatchIndex(text, -1) {
			if rule.secrets == nil {
				detections = appendSpan(detections, rule, match[0], match[1])
				continue
			}
			for _, group := range rule.secrets {
				detections = appendSpan(detections, rule, match[2*group], match[2*group+1])
			}
		}
	}
	return detections, nil
}

// appendSpan skips unmatched (-1) and empty groups: an empty span cannot be masked.
func appendSpan(detections []domain.Detection, rule compiledRule, start, end int) []domain.Detection {
	if start < 0 || end <= start {
		return detections
	}
	return append(detections, domain.Detection{Rule: rule.name, Type: rule.kind, Start: start, End: end})
}
