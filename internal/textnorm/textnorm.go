// Package textnorm normalizes text for deterministic guardrail matching and
// maps every range of the normalized text back to the original text.
//
// Normalize applies, in order:
//
//  1. decoding: the input is read rune by rune as a Go range loop does, so
//     each invalid UTF-8 byte is one original rune and becomes U+FFFD;
//  2. stripping: the invisible formatting and bidirectional controls listed by
//     IsStripped are removed;
//  3. NFKC (golang.org/x/text/unicode/norm), applied to the stripped text so
//     characters split by a stripped rune compose again.
//
// Offsets are expressed in runes (Unicode code points) or in UTF-8 bytes and
// never index a byte as a character. A normalized range always maps to an
// original range that contains every original rune that contributed to it and
// is widened to whole extended grapheme clusters of the original text
// (UAX #29, Unicode 15.0.0). See README.md in this directory for the exact
// mapping contract and its known ambiguities.
package textnorm

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// ErrInvalidRange is returned when a requested range is empty, reversed, out
// of bounds, or not on rune boundaries.
var ErrInvalidRange = errors.New("textnorm: invalid range")

const combiningGraphemeJoiner = "\u034f"

// Span is a half-open range [Start, End).
type Span struct {
	Start int
	End   int
}

// Result is a normalized text with its offset map. It is immutable and safe
// for concurrent use.
type Result struct {
	text string
	// normBytes[i] is the byte offset of normalized rune i; the last entry is
	// len(text).
	normBytes []int
	// origStart[i] and origEnd[i] delimit the original runes that produced
	// normalized rune i. Both are non-decreasing and origStart[i] < origEnd[i].
	origStart []int
	origEnd   []int
	// origBytes[i] is the byte offset of original rune i; the last entry is
	// the original byte length.
	origBytes []int
	// clusterStart[i] and clusterEnd[i] delimit the original grapheme cluster
	// that contains original rune i.
	clusterStart []int
	clusterEnd   []int
}

// Normalize returns the normalized form of s with its offset map.
func Normalize(s string) *Result {
	result := &Result{}

	// Decode the original text and strip invisible controls.
	var (
		stripped      []byte
		strippedBytes []int // byte offset of each kept rune in stripped
		keptOriginal  []int // original rune index of each kept rune
		originalRunes []rune
	)
	for byteOffset, r := range s {
		result.origBytes = append(result.origBytes, byteOffset)
		originalRunes = append(originalRunes, r)
		if IsStripped(r) {
			continue
		}
		strippedBytes = append(strippedBytes, len(stripped))
		keptOriginal = append(keptOriginal, len(originalRunes)-1)
		stripped = utf8.AppendRune(stripped, r)
	}
	result.origBytes = append(result.origBytes, len(s))
	strippedBytes = append(strippedBytes, len(stripped))
	result.clusterStart, result.clusterEnd = clusterBounds(originalRunes)

	// NFKC, one segment at a time. Segments end at normalization boundaries,
	// where normalization restarts, so the concatenation of the normalized
	// segments is the NFKC form of the whole stripped text.
	output := make([]byte, 0, len(stripped))
	emit := func(normalized []byte, start, end int) {
		for len(normalized) > 0 {
			_, size := utf8.DecodeRune(normalized)
			result.normBytes = append(result.normBytes, len(output))
			result.origStart = append(result.origStart, start)
			result.origEnd = append(result.origEnd, end)
			output = append(output, normalized[:size]...)
			normalized = normalized[size:]
		}
	}
	segmentStart := 0 // stripped rune index
	for offset := 0; offset < len(stripped); {
		rest := stripped[offset:]
		if offset > 0 && !norm.NFKC.Properties(rest).BoundaryBefore() {
			// x/text splits runs of more than 30 non-starters and inserts
			// U+034F COMBINING GRAPHEME JOINER (Stream-Safe Text Format,
			// UAX #15). Mirror it so Text matches norm.NFKC.String; the
			// joiner maps to the rune it precedes.
			emit([]byte(combiningGraphemeJoiner), keptOriginal[segmentStart], keptOriginal[segmentStart]+1)
		}
		size := norm.NFKC.QuickSpan(rest)
		unchanged := size > 0
		if !unchanged {
			size = norm.NFKC.NextBoundary(rest, true)
		}
		offset += size
		segmentEnd, found := slices.BinarySearch(strippedBytes, offset)
		if !found || segmentEnd <= segmentStart {
			panic(fmt.Sprintf("textnorm: normalization segment ends off a rune boundary at byte %d", offset))
		}
		input := rest[:size]
		normalized := input
		if !unchanged {
			normalized = norm.NFKC.Bytes(input)
			unchanged = bytes.Equal(normalized, input)
		}
		if unchanged {
			// Text already in NFKC maps rune for rune.
			for index := segmentStart; index < segmentEnd; index++ {
				runeBytes := stripped[strippedBytes[index]:strippedBytes[index+1]]
				emit(runeBytes, keptOriginal[index], keptOriginal[index]+1)
			}
		} else {
			// Every output rune of a rewritten segment maps to all the
			// original runes of the segment, stripped ones in between included.
			emit(normalized, keptOriginal[segmentStart], keptOriginal[segmentEnd-1]+1)
		}
		segmentStart = segmentEnd
	}
	result.normBytes = append(result.normBytes, len(output))
	result.text = string(output)
	return result
}

// clusterBounds returns, for each rune, the bounds of its grapheme cluster.
func clusterBounds(runes []rune) (starts, ends []int) {
	breaks := graphemeBreaks(runes)
	starts = make([]int, len(runes))
	ends = make([]int, len(runes))
	start := 0
	for index := 1; index <= len(runes); index++ {
		if !breaks[index] {
			continue
		}
		for member := start; member < index; member++ {
			starts[member], ends[member] = start, index
		}
		start = index
	}
	return starts, ends
}

// Text returns the normalized text.
func (r *Result) Text() string { return r.text }

// Len returns the number of runes in the normalized text.
func (r *Result) Len() int { return len(r.origStart) }

// OriginalLen returns the number of runes in the original text, counting each
// invalid UTF-8 byte as one rune.
func (r *Result) OriginalLen() int { return len(r.origBytes) - 1 }

// OriginalRunes maps the non-empty normalized rune range [start, end) to the
// original rune range that covers every contributing original rune, widened to
// whole original grapheme clusters.
func (r *Result) OriginalRunes(start, end int) (Span, error) {
	if start < 0 || start >= end || end > r.Len() {
		return Span{}, fmt.Errorf("%w: rune range [%d,%d) over %d normalized runes", ErrInvalidRange, start, end, r.Len())
	}
	return Span{
		Start: r.clusterStart[r.origStart[start]],
		End:   r.clusterEnd[r.origEnd[end-1]-1],
	}, nil
}

// OriginalBytes maps the non-empty normalized byte range [start, end), which
// must lie on rune boundaries of Text, to the original byte range with the
// same coverage as OriginalRunes. This is the form returned by regexp index
// methods and expected by domain.Detection.
func (r *Result) OriginalBytes(start, end int) (Span, error) {
	runeStart, okStart := slices.BinarySearch(r.normBytes, start)
	runeEnd, okEnd := slices.BinarySearch(r.normBytes, end)
	if !okStart || !okEnd || runeStart >= runeEnd {
		return Span{}, fmt.Errorf("%w: byte range [%d,%d) over %d normalized bytes", ErrInvalidRange, start, end, len(r.text))
	}
	span, err := r.OriginalRunes(runeStart, runeEnd)
	if err != nil {
		return Span{}, err
	}
	return Span{Start: r.origBytes[span.Start], End: r.origBytes[span.End]}, nil
}
