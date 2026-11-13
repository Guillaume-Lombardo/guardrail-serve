package guardrails

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/textnorm"
	"github.com/g1lom/guardrail-serve/internal/validators"
)

// NamedPattern is one YAML rule. Type labels findings (and typed masks); when
// empty, the detector's default type applies.
type NamedPattern struct {
	Name      string          `yaml:"name"`
	Type      string          `yaml:"type"`
	Regex     string          `yaml:"regex"`
	Validator validators.Kind `yaml:"validator,omitempty"`
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
	name      string
	kind      string
	regex     *regexp.Regexp
	secrets   []int
	validator validators.Kind
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
		if pattern.Validator != "" {
			if name != "detect_pii" {
				return nil, fmt.Errorf("%s: validators require detect_pii", name)
			}
			if _, err := validators.ParseKind(string(pattern.Validator)); err != nil {
				return nil, err
			}
		}
		rule := compiledRule{name: pattern.Name, kind: kind, regex: re, validator: pattern.Validator}
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
	var normalized *textnorm.Result
	if d.name == "detect_pii" || d.name == "prompt_injection" {
		if !utf8.ValidString(text) || strings.ContainsRune(text, utf8.RuneError) {
			return nil, fmt.Errorf("%s: invalid UTF-8 or replacement character in input", d.name)
		}
		normalized = textnorm.Normalize(text)
		text = normalized.Text()
	}
	add := func(rule compiledRule, start, end int) error {
		if start < 0 || end <= start {
			return nil
		}
		if d.name == "detect_pii" {
			end = piiCandidateEnd(rule, text, start, end)
			if end <= start {
				return nil
			}
		}
		if normalized != nil {
			span, err := normalized.OriginalBytes(start, end)
			if err != nil {
				return fmt.Errorf("%s: original span: %w", d.name, err)
			}
			start, end = span.Start, span.End
		}
		detections = appendSpan(detections, rule, start, end)
		return nil
	}
	for _, rule := range d.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, match := range rule.matches(text) {
			if rule.secrets == nil {
				if err := add(rule, match[0], match[1]); err != nil {
					return nil, err
				}
				continue
			}
			for _, group := range rule.secrets {
				if err := add(rule, match[2*group], match[2*group+1]); err != nil {
					return nil, err
				}
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

// matches keeps grouped IBANs independent even when a greedy candidate also
// consumes the beginning of the next identifier. Other rules stay unchanged.
func (rule compiledRule) matches(text string) [][]int {
	if rule.validator != validators.KindIBAN {
		return rule.regex.FindAllStringSubmatchIndex(text, -1)
	}
	var matches [][]int
	for offset := 0; offset < len(text); {
		match := rule.regex.FindStringSubmatchIndex(text[offset:])
		if match == nil {
			break
		}
		for i := range match {
			if match[i] >= 0 {
				match[i] += offset
			}
		}
		matches = append(matches, match)
		_, size := utf8.DecodeRuneInString(text[match[0]:])
		offset = match[0] + size
	}
	return matches
}
