package guardrails

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/secrets"
	"github.com/g1lom/guardrail-serve/internal/textnorm"
)

var legacyAWSAccessID = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

// SecretDetector adapts native findings to original byte spans for the engine.
// An explicit legacy override retains its original regex and offset semantics.
type SecretDetector struct {
	scanner  *secrets.Scanner
	override *RegexDetector
}

// NewSecretDetector uses native detection for nil patterns. A non-nil list
// replaces native detection entirely, including an explicitly empty list.
func NewSecretDetector(patterns []NamedPattern) (*SecretDetector, error) {
	d := &SecretDetector{}
	var err error
	if patterns != nil {
		d.override, err = newRegexDetector("detect_secret", "SECRET", "Secret detected.", spanSecretGroup, patterns)
	} else {
		d.scanner, err = secrets.New(secrets.DefaultConfig())
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}
func (d *SecretDetector) Name() string        { return "detect_secret" }
func (d *SecretDetector) BlockReason() string { return "Secret detected." }
func (d *SecretDetector) Supports(stage domain.Stage) bool {
	return stage == domain.StageInput || stage == domain.StageOutput
}
func (d *SecretDetector) Rules() []string {
	if d.override != nil {
		return d.override.Rules()
	}
	return append(d.scanner.Rules(), "compat:aws_access_key_id")
}
func (d *SecretDetector) Detect(ctx context.Context, text string) ([]domain.Detection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.override != nil {
		return d.override.Detect(ctx, text)
	}
	if !utf8.ValidString(text) || strings.ContainsRune(text, utf8.RuneError) {
		return nil, fmt.Errorf("detect_secret: invalid UTF-8 or replacement character in input")
	}
	normalized := textnorm.Normalize(text)
	findings, err := d.scanner.Scan(ctx, normalized.Text())
	if err != nil {
		return nil, err
	}
	detections := make([]domain.Detection, 0, len(findings))
	for _, f := range findings {
		span, err := normalized.OriginalBytes(f.ByteStart, f.ByteEnd)
		if err != nil {
			return nil, fmt.Errorf("detect_secret: original span: %w", err)
		}
		detections = append(detections, domain.Detection{Rule: f.Rule, Type: f.Type, Start: span.Start, End: span.End, Score: f.Score})
	}
	// Preserve the historical AWS access-id shape, including examples that
	// upstream allowlists omit. Never relax native provider allowlists globally.
	cursor, maxEnd := 0, -1
	for _, m := range legacyAWSAccessID.FindAllStringIndex(normalized.Text(), -1) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Scanner findings and regex matches are sorted by start: containment
		// takes one forward sweep even for dense adversarial input.
		for cursor < len(findings) && findings[cursor].ByteStart <= m[0] {
			maxEnd = max(maxEnd, findings[cursor].ByteEnd)
			cursor++
		}
		if maxEnd >= m[1] {
			continue
		}
		span, err := normalized.OriginalBytes(m[0], m[1])
		if err != nil {
			return nil, fmt.Errorf("detect_secret: original span: %w", err)
		}
		detections = append(detections, domain.Detection{Rule: "compat:aws_access_key_id", Type: secrets.TypeSecret, Start: span.Start, End: span.End})
	}
	return detections, nil
}
