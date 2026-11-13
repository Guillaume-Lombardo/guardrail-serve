package secrets

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

// High-entropy detection follows detect-secrets Base64HighEntropyString and
// HexHighEntropyString (plugins/high_entropy_strings.py) and its heuristic
// filters (filters/heuristic.py), adapted to free text: candidates are runs of
// the base64 alphabet instead of quoted strings, with explicit length limits
// and context-aware filters.

const (
	ruleEntropyBase64 = "entropy:base64"
	ruleEntropyHex    = "entropy:hex"
)

func isBase64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '-' || c == '_' || c == '='
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// urlPattern finds URLs, whose path segments are evaluated one by one.
var urlPattern = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]{1,15}://[^\s"'<>\x60]+`)

var uuidPattern = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// sequences are the detect-secrets is_sequential_string alphabets.
var sequences = []string{
	"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/",
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ+/",
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"01234567890123456789",
	"0123456789ABCDEFABCDEF0123456789ABCDEFABCDEF",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ=/",
}

// hashContextWords before a hex candidate (same line, hashContextWindow
// bytes) mark it as a digest or object id.
var hashContextWords = setOf("commit", "commits", "sha", "sha1", "sha224", "sha256", "sha384", "sha512", "md5",
	"digest", "checksum", "hash", "revision", "rev", "etag", "fingerprint", "blob", "tree", "parent")

const hashContextWindow = 32

// subresourceIntegrityPrefixes start base64 digests (package lock files,
// HTML integrity attributes).
var subresourceIntegrityPrefixes = []string{"sha1-", "sha256-", "sha384-", "sha512-"}

func scanEntropy(view *textView, assignments []assignment, cfg EntropyConfig) []rawFinding {
	text := view.text
	urls := newSpanIndex(urlPattern.FindAllStringIndex(text, -1))
	var strongSpans, idSpans [][]int
	for _, a := range assignments {
		if a.group != "" {
			strongSpans = append(strongSpans, []int{a.valueStart, a.valueEnd})
		}
		if a.idLike {
			idSpans = append(idSpans, []int{a.valueStart, a.valueEnd})
		}
	}
	strongContext, idValues := newSpanIndex(strongSpans), newSpanIndex(idSpans)
	var findings []rawFinding
	for pos := 0; pos < len(text); {
		if !isBase64Byte(text[pos]) {
			pos++
			continue
		}
		runStart := pos
		for pos < len(text) && isBase64Byte(text[pos]) {
			pos++
		}
		for _, segment := range splitPadding(text, runStart, pos) {
			// A key that names a secret, such as `api_key = <candidate>`.
			strong := strongContext.overlaps(segment[0], segment[1])
			parts := [][2]int{segment}
			if !strong && urls.contains(segment[0], segment[1]) {
				parts = splitByte(text, segment[0], segment[1], '/')
			}
			for _, part := range parts {
				if finding, ok := evaluateCandidate(text, idValues, cfg, part[0], part[1], strong); ok {
					findings = append(findings, finding)
				}
			}
		}
	}
	return findings
}

// splitPadding splits a run at internal '=' sequences: base64 only pads at the
// end, so `name=value` yields two candidates while `abc==` keeps its padding.
func splitPadding(text string, start, end int) [][2]int {
	var segments [][2]int
	segmentStart := start
	for i := start; i < end; {
		if text[i] != '=' {
			i++
			continue
		}
		equalsStart := i
		for i < end && text[i] == '=' {
			i++
		}
		if i < end {
			if equalsStart > segmentStart {
				segments = append(segments, [2]int{segmentStart, equalsStart})
			}
			segmentStart = i
		}
	}
	if end > segmentStart {
		segments = append(segments, [2]int{segmentStart, end})
	}
	return segments
}

func splitByte(text string, start, end int, separator byte) [][2]int {
	var parts [][2]int
	partStart := start
	for i := start; i <= end; i++ {
		if i == end || text[i] == separator {
			if i > partStart {
				parts = append(parts, [2]int{partStart, i})
			}
			partStart = i + 1
		}
	}
	return parts
}

// spanIndex is a sorted list of disjoint byte spans answering overlap and
// containment queries in O(log n), so that context lookups stay linear in
// the number of candidates.
type spanIndex [][2]int

// newSpanIndex sorts spans and merges the overlapping or adjacent ones.
func newSpanIndex(spans [][]int) spanIndex {
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	var index spanIndex
	for _, span := range spans {
		if n := len(index); n > 0 && span[0] <= index[n-1][1] {
			index[n-1][1] = max(index[n-1][1], span[1])
			continue
		}
		index = append(index, [2]int{span[0], span[1]})
	}
	return index
}

// overlaps reports whether [start, end) overlaps a span of the index.
func (index spanIndex) overlaps(start, end int) bool {
	i := sort.Search(len(index), func(i int) bool { return index[i][1] > start })
	return i < len(index) && index[i][0] < end
}

// contains reports whether [start, end) lies inside one span of the index.
func (index spanIndex) contains(start, end int) bool {
	i := sort.Search(len(index), func(i int) bool { return index[i][0] > start }) - 1
	return i >= 0 && end <= index[i][1]
}

func evaluateCandidate(text string, idValues spanIndex, cfg EntropyConfig, start, end int, strong bool) (rawFinding, bool) {
	candidate := text[start:end]
	hex := isAllHex(candidate)
	rule, threshold, minLength := ruleEntropyBase64, cfg.Base64Threshold, cfg.MinBase64Length
	if hex {
		rule, threshold, minLength = ruleEntropyHex, cfg.HexThreshold, cfg.MinHexLength
	}
	if len(candidate) < minLength {
		return rawFinding{}, false
	}
	entropy := shannonEntropy(candidate)
	if hex {
		entropy = hexEntropyAdjust(candidate, entropy)
	}
	if entropy <= threshold {
		return rawFinding{}, false
	}
	// Filters that never describe a real secret, applied in every context.
	if !hasASCIILetter(candidate) || isSequential(candidate) || isTemplatedCandidate(text, start, end) ||
		(start > 0 && text[start-1] == '$') {
		return rawFinding{}, false
	}
	// Filters for identifiers and digests. A key that names a secret wins:
	// `api_key = <40 hex>` is reported even though it looks like a SHA-1.
	if !strong {
		if uuidPattern.MatchString(candidate) || idValues.overlaps(start, end) ||
			isDataURIPayload(text, start) || isSubresourceIntegrity(candidate) ||
			(hex && isLikelyDigest(text, start, candidate)) {
			return rawFinding{}, false
		}
	}
	score := entropy
	return rawFinding{source: SourceEntropy, rule: rule, kind: TypeHighEntropyString, start: start, end: end, score: &score}, true
}

func isAllHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

// hexEntropyAdjust is detect-secrets HexHighEntropyString: all-digit strings
// lose 1.2/log2(len) bits so that numbers rarely pass the threshold.
func hexEntropyAdjust(candidate string, entropy float64) float64 {
	if len(candidate) <= 1 {
		return entropy
	}
	for i := 0; i < len(candidate); i++ {
		if candidate[i] < '0' || candidate[i] > '9' {
			return entropy
		}
	}
	return entropy - 1.2/math.Log2(float64(len(candidate)))
}

func hasASCIILetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// isSequential is detect-secrets is_sequential_string.
func isSequential(candidate string) bool {
	upper := strings.ToUpper(candidate)
	for _, sequence := range sequences {
		if strings.Contains(sequence, upper) {
			return true
		}
	}
	return false
}

// isTemplatedCandidate applies detect-secrets is_templated_secret to the
// characters around the candidate: {x}, <x>, ${x}, {{x}}.
func isTemplatedCandidate(text string, start, end int) bool {
	if start == 0 || end >= len(text) {
		return false
	}
	before, after := text[start-1], text[end]
	return before == '{' && after == '}' || before == '<' && after == '>'
}

func isDataURIPayload(text string, start int) bool {
	const marker = ";base64,"
	return start >= len(marker) && strings.EqualFold(text[start-len(marker):start], marker)
}

func isSubresourceIntegrity(candidate string) bool {
	lower := strings.ToLower(candidate)
	for _, prefix := range subresourceIntegrityPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// isLikelyDigest flags hex that is a git object id or a digest: a bare 40 or
// 64 character string in a single case, or any hex preceded on its line by a
// digest word (commit, sha256, checksum...).
func isLikelyDigest(text string, start int, candidate string) bool {
	if (len(candidate) == 40 || len(candidate) == 64) && singleCase(candidate) {
		return true
	}
	windowStart := max(0, start-hashContextWindow)
	window := text[windowStart:start]
	if newline := strings.LastIndexByte(window, '\n'); newline >= 0 {
		window = window[newline+1:]
	}
	for _, word := range strings.FieldsFunc(strings.ToLower(window), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		if hashContextWords[word] {
			return true
		}
	}
	return false
}

func singleCase(s string) bool {
	return s == strings.ToLower(s) || s == strings.ToUpper(s)
}
