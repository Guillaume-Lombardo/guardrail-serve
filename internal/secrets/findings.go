package secrets

import (
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

// rawFinding is a finding in byte offsets, before overlap resolution and
// rune projection.
type rawFinding struct {
	source Source
	rule   string
	kind   string
	start  int
	end    int
	score  *float64
}

// sourceRank orders sources from the most to the least specific: a provider
// rule explains a span better than a keyword assignment, which explains it
// better than its entropy alone.
func sourceRank(source Source) int {
	switch source {
	case SourceGitleaks:
		return 0
	case SourceKeyword:
		return 1
	default:
		return 2
	}
}

// resolveOverlaps drops exact duplicates and findings whose span lies inside
// the span of a finding from a more specific source. Partial overlaps are
// kept: callers merge them when masking.
func resolveOverlaps(findings []rawFinding) []rawFinding {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.end != b.end {
			return a.end > b.end
		}
		if ra, rb := sourceRank(a.source), sourceRank(b.source); ra != rb {
			return ra < rb
		}
		return a.rule < b.rule
	})
	kept := make([]rawFinding, 0, len(findings))
	for _, candidate := range findings {
		covered := false
		for _, other := range kept {
			if other.start <= candidate.start && candidate.end <= other.end {
				sameSpan := other.start == candidate.start && other.end == candidate.end
				if sourceRank(other.source) < sourceRank(candidate.source) ||
					(other.source == candidate.source && sameSpan && (candidate.source != SourceGitleaks || other.rule == candidate.rule)) {
					covered = true
					break
				}
			}
		}
		if !covered {
			kept = append(kept, candidate)
		}
	}
	return kept
}

// textView holds a text and lazily computed indexes shared by the sources.
type textView struct {
	text     string
	lower    string
	newlines []int
}

func newTextView(text string) *textView {
	view := &textView{text: text}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			view.newlines = append(view.newlines, i)
		}
	}
	return view
}

// lowered returns the lower-cased text. It is only used for keyword presence
// tests, never for offsets (lower-casing may change byte lengths).
func (v *textView) lowered() string {
	if v.lower == "" {
		v.lower = strings.ToLower(v.text)
	}
	return v.lower
}

// lineNumber returns the zero-based line containing byte offset pos.
func (v *textView) lineNumber(pos int) int {
	return sort.SearchInts(v.newlines, pos)
}

// lineSpan returns the byte span of the lines covering [start, end), newline
// characters excluded.
func (v *textView) lineSpan(start, end int) (int, int) {
	lineStart := 0
	if i := v.lineNumber(start); i > 0 {
		lineStart = v.newlines[i-1] + 1
	}
	lineEnd := len(v.text)
	last := end
	if last > start {
		last--
	}
	if i := v.lineNumber(last); i < len(v.newlines) {
		lineEnd = v.newlines[i]
	}
	return lineStart, lineEnd
}

// project converts byte offsets into rune offsets and builds the public
// findings, sorted by start, end, source rank and rule.
func (v *textView) project(raw []rawFinding) []Finding {
	if len(raw) == 0 {
		return nil
	}
	sort.SliceStable(raw, func(i, j int) bool {
		a, b := raw[i], raw[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.end != b.end {
			return a.end < b.end
		}
		if ra, rb := sourceRank(a.source), sourceRank(b.source); ra != rb {
			return ra < rb
		}
		return a.rule < b.rule
	})
	offsets := make([]int, 0, 2*len(raw))
	for _, finding := range raw {
		offsets = append(offsets, finding.start, finding.end)
	}
	sort.Ints(offsets)
	runes := make(map[int]int, len(offsets))
	position, count := 0, 0
	for _, offset := range offsets {
		if _, done := runes[offset]; done {
			continue
		}
		count += utf8.RuneCountInString(v.text[position:offset])
		position = offset
		runes[offset] = count
	}
	findings := make([]Finding, len(raw))
	for i, finding := range raw {
		findings[i] = Finding{
			Source:    finding.source,
			Rule:      finding.rule,
			Type:      finding.kind,
			Start:     runes[finding.start],
			End:       runes[finding.end],
			ByteStart: finding.start,
			ByteEnd:   finding.end,
			Score:     finding.score,
		}
	}
	return findings
}

// shannonEntropy is the Shannon entropy, in bits per character, of the code
// points of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	// Sum in a fixed order so the result is bit-for-bit deterministic.
	keys := make([]rune, 0, len(counts))
	for r := range counts {
		keys = append(keys, r)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	entropy := 0.0
	for _, r := range keys {
		p := float64(counts[r]) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}
