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
//
// Channel and ExemptQuotedAnalysis are prompt_injection options (ADR 0018):
// channel "folded" matches textnorm.Fold, and exempt_quoted_analysis ignores
// folded matches inside a quotation that the rest of the text only analyses.
type NamedPattern struct {
	Name                 string          `yaml:"name"`
	Type                 string          `yaml:"type"`
	Regex                string          `yaml:"regex"`
	Validator            validators.Kind `yaml:"validator,omitempty"`
	Channel              string          `yaml:"channel,omitempty"`
	ExemptQuotedAnalysis bool            `yaml:"exempt_quoted_analysis,omitempty"`
}

var findingTypePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// spanSelector chooses the reported span inside one regex match.
type spanSelector int

const (
	// spanSecretGroup reports every non-empty capture group named "secret".
	spanSecretGroup spanSelector = iota
	// spanWholeMatch reports the whole non-empty match, or every non-empty
	// capture group named "match" when the rule has one (so a rule can require
	// context, such as a clause start, without reporting it).
	spanWholeMatch
)

type compiledRule struct {
	name      string
	kind      string
	regex     *regexp.Regexp
	groups    []int // reported capture groups; nil reports the whole match
	validator validators.Kind
	channel   MatchChannel
	exempt    bool
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
		channel, err := ParseMatchChannel(pattern.Channel)
		if err != nil {
			return nil, fmt.Errorf("%s pattern %d (%q): %w", name, index, pattern.Name, err)
		}
		if channel == ChannelFolded && name != "prompt_injection" {
			return nil, fmt.Errorf("%s pattern %d (%q): channel %q requires prompt_injection", name, index, pattern.Name, channel)
		}
		if pattern.ExemptQuotedAnalysis && channel != ChannelFolded {
			return nil, fmt.Errorf("%s pattern %d (%q): exempt_quoted_analysis requires channel %q", name, index, pattern.Name, ChannelFolded)
		}
		rule := compiledRule{name: pattern.Name, kind: kind, regex: re, validator: pattern.Validator, channel: channel, exempt: pattern.ExemptQuotedAnalysis}
		groupName := "match"
		if selector == spanSecretGroup {
			groupName = "secret"
		}
		for group, subexp := range re.SubexpNames() {
			if group > 0 && subexp == groupName {
				rule.groups = append(rule.groups, group)
			}
		}
		if selector == spanSecretGroup && len(rule.groups) == 0 {
			return nil, fmt.Errorf("%s pattern %d (%q): a (?P<secret>...) group is required", name, index, pattern.Name)
		}
		rules = append(rules, rule)
	}
	return &RegexDetector{name: name, blockReason: blockReason, rules: rules}, nil
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
	// The folded view and its quoted mentions are computed once, on demand.
	var folded *textnorm.Folded
	var mentions []textnorm.Span
	add := func(rule compiledRule, scanned string, start, end int) error {
		if start < 0 || end <= start {
			return nil
		}
		if d.name == "detect_pii" {
			end = piiCandidateEnd(rule, scanned, start, end)
			if end <= start {
				return nil
			}
		}
		var span textnorm.Span
		var err error
		switch {
		case rule.channel == ChannelFolded:
			if rule.exempt && insideAny(mentions, start, end) {
				return nil
			}
			span, err = folded.OriginalBytes(start, end)
		case normalized != nil:
			span, err = normalized.OriginalBytes(start, end)
		default:
			span = textnorm.Span{Start: start, End: end}
		}
		if err != nil {
			return fmt.Errorf("%s: original span: %w", d.name, err)
		}
		detections = appendSpan(detections, rule, span.Start, span.End)
		return nil
	}
	for _, rule := range d.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		scanned := text
		if rule.channel == ChannelFolded {
			if folded == nil {
				folded = normalized.Fold()
				mentions = quotedMentions(folded)
			}
			scanned = folded.Text()
		}
		for _, match := range rule.matches(scanned) {
			if rule.groups == nil {
				if err := add(rule, scanned, match[0], match[1]); err != nil {
					return nil, err
				}
				continue
			}
			for _, group := range rule.groups {
				if err := add(rule, scanned, match[2*group], match[2*group+1]); err != nil {
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
