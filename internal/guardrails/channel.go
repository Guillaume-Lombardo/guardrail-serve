package guardrails

import "fmt"

// MatchChannel selects the text a YAML rule is matched against.
type MatchChannel string

const (
	// ChannelNormalized matches the normalized text (strip + NFKC, ADR 0013).
	// It is the default when a rule sets no channel.
	ChannelNormalized MatchChannel = "normalized"
	// ChannelFolded matches the matching-only folded text of textnorm.Fold
	// (lowercase, no diacritics, homoglyphs, digits as letters, spaced letters
	// joined). It is only available to prompt_injection (ADR 0018): folding
	// would corrupt the values PII and secret rules must report.
	ChannelFolded MatchChannel = "folded"
)

// ParseMatchChannel validates a channel; the empty string is the default.
func ParseMatchChannel(value string) (MatchChannel, error) {
	switch MatchChannel(value) {
	case "", ChannelNormalized:
		return ChannelNormalized, nil
	case ChannelFolded:
		return ChannelFolded, nil
	}
	return "", fmt.Errorf("unknown channel %q (expected %q or %q)", value, ChannelNormalized, ChannelFolded)
}

// String returns the YAML spelling of the channel.
func (c MatchChannel) String() string { return string(c) }
