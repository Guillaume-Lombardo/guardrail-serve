// Package secrets is a native, deterministic secret detector for free text.
//
// It combines three sources, each producing findings with Unicode code point
// offsets into the original text:
//
//   - gitleaks: the vendored gitleaks default rules (MIT), evaluated with the
//     gitleaks semantics for keywords, secret groups, entropy and allowlists;
//   - keyword: secret assignments such as `password = "..."` or
//     `api_key: ...`, after the keyword approach of detect-secrets;
//   - entropy: high-entropy base64 and hex candidates, with the Shannon
//     thresholds and false-positive filters of detect-secrets (Apache-2.0).
//
// The package depends only on the standard library. It does not know about
// policies, HTTP or the guardrail engine: callers adapt findings to their own
// contracts. Findings and errors never contain matched values.
package secrets

import (
	"context"
	"fmt"
	"math"
	"sort"
)

// Source identifies the mechanism that produced a finding.
type Source string

const (
	SourceGitleaks Source = "gitleaks"
	SourceKeyword  Source = "keyword"
	SourceEntropy  Source = "entropy"
)

// Finding types. They match the guardrail finding type syntax so callers can
// use them directly in typed masks.
const (
	TypeSecret            = "SECRET"
	TypeHighEntropyString = "HIGH_ENTROPY_STRING"
)

// Finding is one detected secret span. Start and End are Unicode code point
// (rune) offsets in the scanned text, start inclusive and end exclusive;
// ByteStart and ByteEnd are the same span in bytes, on rune boundaries.
// Score is the Shannon entropy of the span for entropy findings and nil
// otherwise. A Finding never carries the matched value.
type Finding struct {
	Source    Source
	Rule      string
	Type      string
	Start     int
	End       int
	ByteStart int
	ByteEnd   int
	Score     *float64
}

// GitleaksConfig controls the vendored gitleaks rules.
type GitleaksConfig struct {
	Enabled bool
	// DisabledRules lists gitleaks rule ids (without the "gitleaks:" prefix)
	// to skip. Unknown or excluded ids are construction errors.
	DisabledRules []string
}

// KeywordConfig controls contextual secret assignments.
type KeywordConfig struct {
	Enabled bool
}

// EntropyConfig controls high-entropy candidates. A candidate is reported
// when its Shannon entropy is strictly greater than the threshold of its
// alphabet and it is at least the minimum length (in characters).
type EntropyConfig struct {
	Enabled         bool
	Base64Threshold float64
	HexThreshold    float64
	MinBase64Length int
	MinHexLength    int
}

// Config is the explicit construction input of a Scanner.
type Config struct {
	Gitleaks GitleaksConfig
	Keywords KeywordConfig
	Entropy  EntropyConfig
}

// Default thresholds and candidate limits.
const (
	DefaultBase64Threshold = 4.5
	DefaultHexThreshold    = 3.0
	DefaultMinBase64Length = 20
	DefaultMinHexLength    = 16
	// maxEntropyThreshold is the upper bound accepted by detect-secrets.
	maxEntropyThreshold = 8.0
)

// DefaultConfig enables every source with the default thresholds.
func DefaultConfig() Config {
	return Config{
		Gitleaks: GitleaksConfig{Enabled: true},
		Keywords: KeywordConfig{Enabled: true},
		Entropy: EntropyConfig{
			Enabled:         true,
			Base64Threshold: DefaultBase64Threshold,
			HexThreshold:    DefaultHexThreshold,
			MinBase64Length: DefaultMinBase64Length,
			MinHexLength:    DefaultMinHexLength,
		},
	}
}

// Scanner detects secrets in texts. It is immutable and safe for concurrent
// use.
type Scanner struct {
	gitleaks []gitleaksRule
	global   []gitleaksAllowlist
	keywords bool
	entropy  *EntropyConfig
}

// New validates cfg and builds a Scanner.
func New(cfg Config) (*Scanner, error) {
	if !cfg.Gitleaks.Enabled && !cfg.Keywords.Enabled && !cfg.Entropy.Enabled {
		return nil, fmt.Errorf("secrets: at least one source must be enabled")
	}
	if !cfg.Gitleaks.Enabled && len(cfg.Gitleaks.DisabledRules) > 0 {
		return nil, fmt.Errorf("secrets: gitleaks disabled rules require gitleaks to be enabled")
	}
	scanner := &Scanner{keywords: cfg.Keywords.Enabled}
	if cfg.Gitleaks.Enabled {
		set, err := defaultGitleaksRules()
		if err != nil {
			return nil, fmt.Errorf("secrets: vendored gitleaks rules: %w", err)
		}
		rules, err := set.active(cfg.Gitleaks.DisabledRules)
		if err != nil {
			return nil, fmt.Errorf("secrets: %w", err)
		}
		scanner.gitleaks = rules
		scanner.global = set.global
	}
	if cfg.Entropy.Enabled {
		entropy := cfg.Entropy
		if err := validateThreshold("base64", entropy.Base64Threshold); err != nil {
			return nil, err
		}
		if err := validateThreshold("hex", entropy.HexThreshold); err != nil {
			return nil, err
		}
		if entropy.MinBase64Length < 1 || entropy.MinHexLength < 1 {
			return nil, fmt.Errorf("secrets: entropy minimum lengths must be positive")
		}
		scanner.entropy = &entropy
	}
	return scanner, nil
}

func validateThreshold(name string, value float64) error {
	if math.IsNaN(value) || value <= 0 || value > maxEntropyThreshold {
		return fmt.Errorf("secrets: %s entropy threshold must be in (0, %g]", name, maxEntropyThreshold)
	}
	return nil
}

// Rules lists the rule names the scanner can report, sorted.
func (s *Scanner) Rules() []string {
	var names []string
	for _, rule := range s.gitleaks {
		names = append(names, gitleaksRulePrefix+rule.id)
	}
	if s.keywords {
		names = append(names, keywordRuleNames()...)
	}
	if s.entropy != nil {
		names = append(names, ruleEntropyBase64, ruleEntropyHex)
	}
	sort.Strings(names)
	return names
}

// ExcludedGitleaksRules lists vendored rules that never apply to free text,
// with the reason. They cannot be enabled.
func ExcludedGitleaksRules() ([]RuleExclusion, error) {
	set, err := defaultGitleaksRules()
	if err != nil {
		return nil, err
	}
	return append([]RuleExclusion(nil), set.excluded...), nil
}

// Scan returns the findings of text, sorted by start, end, source and rule.
// The only possible error is the context error.
func (s *Scanner) Scan(ctx context.Context, text string) ([]Finding, error) {
	if text == "" {
		return nil, ctx.Err()
	}
	view := newTextView(text)
	var raw []rawFinding
	if len(s.gitleaks) > 0 {
		found, err := scanGitleaks(ctx, view, s.gitleaks, s.global)
		if err != nil {
			return nil, err
		}
		raw = append(raw, found...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var assignments []assignment
	if s.keywords || s.entropy != nil {
		assignments = findAssignments(view)
	}
	if s.keywords {
		raw = append(raw, scanKeywords(view, assignments)...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.entropy != nil {
		raw = append(raw, scanEntropy(view, assignments, *s.entropy)...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return view.project(resolveOverlaps(raw)), nil
}
