package textnorm

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

type rangeCase struct {
	start, end int // normalized runes
	want       Span
}

func TestNormalizeFixtures(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		text   string
		ranges []rangeCase
	}{
		{
			name: "ascii identity", input: "hello", text: "hello",
			ranges: []rangeCase{{0, 5, Span{0, 5}}, {1, 3, Span{1, 3}}, {4, 5, Span{4, 5}}},
		},
		{
			name: "ligature expansion", input: "\ufb01le", text: "file",
			ranges: []rangeCase{{0, 1, Span{0, 1}}, {1, 2, Span{0, 1}}, {1, 3, Span{0, 2}}, {2, 4, Span{1, 3}}},
		},
		{
			name: "square unit expansion", input: "5\u338f", text: "5kg",
			ranges: []rangeCase{{1, 2, Span{1, 2}}, {2, 3, Span{1, 2}}, {0, 1, Span{0, 1}}},
		},
		{
			name: "roman numeral expansion", input: "\u216b!", text: "XII!",
			ranges: []rangeCase{{1, 2, Span{0, 1}}, {3, 4, Span{1, 2}}},
		},
		{
			name: "arabic ligature expansion keeps non-latin letters", input: "\ufdfa.", text: "\u0635\u0644\u0649 \u0627\u0644\u0644\u0647 \u0639\u0644\u064a\u0647 \u0648\u0633\u0644\u0645.",
			ranges: []rangeCase{{0, 3, Span{0, 1}}, {18, 19, Span{1, 2}}},
		},
		{
			name: "fullwidth one to one", input: "\uff21\uff22\uff23", text: "ABC",
			ranges: []rangeCase{{0, 1, Span{0, 1}}, {1, 3, Span{1, 3}}},
		},
		{
			name: "canonical composition contracts length", input: "e\u0301te\u0301", text: "\u00e9t\u00e9",
			ranges: []rangeCase{{0, 1, Span{0, 2}}, {1, 2, Span{2, 3}}, {2, 3, Span{3, 5}}, {0, 3, Span{0, 5}}},
		},
		{
			name: "canonical reordering of combining marks", input: "q\u0307\u0323x", text: "q\u0323\u0307x",
			ranges: []rangeCase{{0, 1, Span{0, 3}}, {1, 2, Span{0, 3}}, {3, 4, Span{3, 4}}},
		},
		{
			name: "combining marks without precomposed form stay one grapheme", input: "a\u0328\u0301b", text: "\u0105\u0301b",
			ranges: []rangeCase{{0, 1, Span{0, 3}}, {1, 2, Span{0, 3}}, {2, 3, Span{3, 4}}},
		},
		{
			name: "hangul jamo composition", input: "\u1100\u1161\u11a8!", text: "\uac01!",
			ranges: []rangeCase{{0, 1, Span{0, 3}}, {1, 2, Span{3, 4}}},
		},
		{
			name: "leading deletion", input: "\u200bsecret", text: "secret",
			ranges: []rangeCase{{0, 6, Span{1, 7}}, {0, 1, Span{1, 2}}},
		},
		{
			name: "middle deletion", input: "se\u200b\u2060cret", text: "secret",
			ranges: []rangeCase{{0, 6, Span{0, 8}}, {0, 2, Span{0, 2}}, {2, 6, Span{4, 8}}, {1, 3, Span{1, 5}}},
		},
		{
			name: "trailing deletion", input: "abc\u202e\u2069", text: "abc",
			ranges: []rangeCase{{0, 3, Span{0, 3}}, {2, 3, Span{2, 3}}},
		},
		{
			name: "deletion between base and combining mark recomposes", input: "e\u200b\u0301!", text: "\u00e9!",
			ranges: []rangeCase{{0, 1, Span{0, 3}}, {1, 2, Span{3, 4}}},
		},
		{
			name: "bidi controls around non-latin text", input: "\u202b\u05e9\u05dc\u05d5\u05dd\u202c \u200f\u0645\u0631\u062d\u0628\u0627", text: "\u05e9\u05dc\u05d5\u05dd \u0645\u0631\u062d\u0628\u0627",
			ranges: []rangeCase{{0, 4, Span{1, 5}}, {5, 10, Span{8, 13}}, {0, 10, Span{1, 13}}},
		},
		{
			name: "devanagari and cjk unchanged", input: "\u0928\u092e\u0938\u094d\u0924\u0947 \u4e16\u754c", text: "\u0928\u092e\u0938\u094d\u0924\u0947 \u4e16\u754c",
			ranges: []rangeCase{{7, 9, Span{7, 9}}, {2, 4, Span{2, 4}}},
		},
		{
			name: "devanagari conjunct is two unicode 15.0 clusters", input: "\u0915\u094d\u0937", text: "\u0915\u094d\u0937",
			ranges: []rangeCase{{0, 1, Span{0, 2}}, {1, 2, Span{0, 2}}, {2, 3, Span{2, 3}}},
		},
		{
			name: "emoji zwj sequence widened to its grapheme", input: "\U0001f469\u200d\U0001f4bb ok", text: "\U0001f469\U0001f4bb ok",
			ranges: []rangeCase{{0, 1, Span{0, 3}}, {1, 2, Span{0, 3}}, {3, 5, Span{4, 6}}},
		},
		{
			name: "regional indicator pair widened", input: "\U0001f1eb\U0001f1f7\U0001f1e9\U0001f1ea", text: "\U0001f1eb\U0001f1f7\U0001f1e9\U0001f1ea",
			ranges: []rangeCase{{0, 1, Span{0, 2}}, {1, 3, Span{0, 4}}, {3, 4, Span{2, 4}}},
		},
		{
			name: "invalid utf8 byte is one rune", input: "a\xffb", text: "a\ufffdb",
			ranges: []rangeCase{{1, 2, Span{1, 2}}, {0, 3, Span{0, 3}}},
		},
		{
			name: "no-break space becomes space", input: "a\u00a0b", text: "a b",
			ranges: []rangeCase{{1, 2, Span{1, 2}}},
		},
		{
			name: "fullwidth obfuscation with zero width space", input: "\uff29\uff47\u200b\uff4e\uff4f\uff52\uff45", text: "Ignore",
			ranges: []rangeCase{{0, 6, Span{0, 7}}, {2, 3, Span{3, 4}}},
		},
		{
			name: "everything stripped", input: "\u200b\u200e\ufeff", text: "",
		},
		{
			name: "empty", input: "", text: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Normalize(test.input)
			if result.Text() != test.text {
				t.Fatalf("Text() = %q, want %q", result.Text(), test.text)
			}
			if result.Len() != utf8.RuneCountInString(test.text) {
				t.Fatalf("Len() = %d, want %d", result.Len(), utf8.RuneCountInString(test.text))
			}
			if result.OriginalLen() != utf8.RuneCountInString(test.input) {
				t.Fatalf("OriginalLen() = %d, want %d", result.OriginalLen(), utf8.RuneCountInString(test.input))
			}
			for _, r := range test.ranges {
				got, err := result.OriginalRunes(r.start, r.end)
				if err != nil {
					t.Fatalf("OriginalRunes(%d, %d): %v", r.start, r.end, err)
				}
				if got != r.want {
					t.Errorf("OriginalRunes(%d, %d) = %v, want %v", r.start, r.end, got, r.want)
				}
			}
			checkInvariants(t, test.input, result)
		})
	}
}

func TestOriginalBytes(t *testing.T) {
	// "ﬁ" is 3 bytes, "é" from e+U+0301 is 3 original bytes, ZWSP is 3 bytes.
	input := "x\ufb01\u200be\u0301!"
	result := Normalize(input)
	if result.Text() != "xfi\u00e9!" {
		t.Fatalf("Text() = %q", result.Text())
	}
	tests := []struct {
		start, end int
		want       Span
	}{
		{0, 1, Span{0, 1}},  // x
		{1, 2, Span{1, 4}},  // f -> ﬁ
		{1, 3, Span{1, 4}},  // fi -> ﬁ
		{3, 5, Span{7, 10}}, // é -> e + U+0301
		{2, 5, Span{1, 10}}, // ié -> ﬁ, ZWSP, e, U+0301
		{5, 6, Span{10, 11}},
	}
	for _, test := range tests {
		got, err := result.OriginalBytes(test.start, test.end)
		if err != nil {
			t.Fatalf("OriginalBytes(%d, %d): %v", test.start, test.end, err)
		}
		if got != test.want {
			t.Errorf("OriginalBytes(%d, %d) = %v, want %v", test.start, test.end, got, test.want)
		}
		if got := input[got.Start:got.End]; !utf8.ValidString(got) {
			t.Errorf("OriginalBytes(%d, %d) slices %q off rune boundaries", test.start, test.end, got)
		}
	}
}

func TestInvalidRanges(t *testing.T) {
	result := Normalize("a\u00e9b") // 3 runes, 4 bytes
	for _, r := range [][2]int{{-1, 1}, {1, 1}, {2, 1}, {0, 4}, {3, 4}} {
		if _, err := result.OriginalRunes(r[0], r[1]); !errors.Is(err, ErrInvalidRange) {
			t.Errorf("OriginalRunes(%d, %d) error = %v, want ErrInvalidRange", r[0], r[1], err)
		}
	}
	for _, r := range [][2]int{{-1, 1}, {1, 1}, {2, 3}, {1, 2}, {0, 5}, {4, 5}, {3, 1}} {
		if _, err := result.OriginalBytes(r[0], r[1]); !errors.Is(err, ErrInvalidRange) {
			t.Errorf("OriginalBytes(%d, %d) error = %v, want ErrInvalidRange", r[0], r[1], err)
		}
	}
	empty := Normalize("\u200b")
	if _, err := empty.OriginalRunes(0, 1); !errors.Is(err, ErrInvalidRange) {
		t.Errorf("OriginalRunes on empty text error = %v, want ErrInvalidRange", err)
	}
}

func TestStreamSafeSegmentsMatchXText(t *testing.T) {
	for _, input := range []string{
		"x" + strings.Repeat("\u0301", 35),
		"a" + strings.Repeat("\u0323\u0301", 40),
		strings.Repeat("\u0301", 70) + "b",
		"\ufb01" + strings.Repeat("\u0301", 31),
		"e" + strings.Repeat("\u200b\u0301", 40),
	} {
		result := Normalize(input)
		if want := norm.NFKC.String(stripAll(input)); result.Text() != want {
			t.Errorf("Text() = %q, want %q", result.Text(), want)
		}
		checkInvariants(t, input, result)
	}
}

func TestIsStrippedSet(t *testing.T) {
	want := map[rune]bool{0x00ad: true, 0x061c: true, 0x180e: true, 0xfeff: true}
	for _, block := range [][2]rune{{0x200b, 0x200f}, {0x202a, 0x202e}, {0x2060, 0x2064}, {0x2066, 0x2069}} {
		for r := block[0]; r <= block[1]; r++ {
			want[r] = true
		}
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if IsStripped(r) != want[r] {
			t.Fatalf("IsStripped(U+%04X) = %v, want %v", r, IsStripped(r), want[r])
		}
		if want[r] && unicode.IsLetter(r) {
			t.Fatalf("stripped rune U+%04X is a letter", r)
		}
	}
}

// TestNFKCNeverProducesStrippedRunes proves that stripping before NFKC is
// enough: no code point normalizes to a sequence containing a stripped rune.
func TestNFKCNeverProducesStrippedRunes(t *testing.T) {
	buffer := make([]byte, 0, utf8.UTFMax)
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if IsStripped(r) || !utf8.ValidRune(r) {
			continue
		}
		buffer = utf8.AppendRune(buffer[:0], r)
		if norm.NFKC.IsNormal(buffer) {
			continue
		}
		for _, produced := range norm.NFKC.String(string(buffer)) {
			if IsStripped(produced) {
				t.Fatalf("NFKC(U+%04X) produces stripped U+%04X", r, produced)
			}
		}
	}
}

var invariantCorpus = []string{
	"", "plain ascii text", "\ufb01\ufb02\ufb03", "\u338f\u33a1\u2474", "e\u0301\u0302\u0303",
	"\u1100\u1161\u11a8\u1100\u1161", "\uac00\u11a8", "\u200b\u200c\u200d", "a\u200db",
	"\U0001f468\u200d\U0001f469\u200d\U0001f467 family", "\U0001f44d\U0001f3fd", "\r\n\r\n",
	"\u0600\u0661\u0662", "\u0915\u094d\u0937", "a\xff\xfe\xc3", "\xe2\x80", "\u01c5\u01c8\u01cb", "\u216b\u0301",
	"\u202eevil\u202c", "\uff29\uff47\uff4e\uff4f\uff52\uff45 \uff50\uff52\uff45\uff56\uff49\uff4f\uff55\uff53",
	"x" + strings.Repeat("\u0301", 33), "\u0301leading mark", "\u3131\u314f", "\u00c5\u212bA\u030a",
}

func TestInvariantsCorpus(t *testing.T) {
	for _, input := range invariantCorpus {
		checkInvariants(t, input, Normalize(input))
	}
}

func FuzzNormalize(f *testing.F) {
	for _, input := range invariantCorpus {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 256 {
			t.Skip()
		}
		checkInvariants(t, input, Normalize(input))
	})
}

// stripAll applies the decoding and stripping stages independently of
// Normalize.
func stripAll(input string) string {
	var builder strings.Builder
	for _, r := range input {
		if !IsStripped(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func withoutCGJ(text string) string {
	return strings.ReplaceAll(text, combiningGraphemeJoiner, "")
}

func checkInvariants(t *testing.T, input string, result *Result) {
	t.Helper()
	text := result.Text()
	if want := norm.NFKC.String(stripAll(input)); text != want {
		t.Fatalf("%q: Text() = %q, want NFKC(strip) %q", input, text, want)
	}
	if again := Normalize(text).Text(); again != text {
		t.Fatalf("%q: normalization is not idempotent: %q -> %q", input, text, again)
	}
	for _, r := range text {
		if IsStripped(r) {
			t.Fatalf("%q: normalized text contains stripped U+%04X", input, r)
		}
	}

	originalRunes := []rune(input)
	normalizedRunes := []rune(text)
	if len(originalRunes) != result.OriginalLen() || len(normalizedRunes) != result.Len() {
		t.Fatalf("%q: lengths %d/%d, want %d/%d", input, result.OriginalLen(), result.Len(), len(originalRunes), len(normalizedRunes))
	}
	breaks := graphemeBreaks(originalRunes)
	runeByteOffsets := make([]int, 0, len(normalizedRunes)+1)
	for offset := range text {
		runeByteOffsets = append(runeByteOffsets, offset)
	}
	runeByteOffsets = append(runeByteOffsets, len(text))
	originalByteOffsets := make([]int, 0, len(originalRunes)+1)
	for offset := range input {
		originalByteOffsets = append(originalByteOffsets, offset)
	}
	originalByteOffsets = append(originalByteOffsets, len(input))

	previous := Span{}
	for start := 0; start < len(normalizedRunes); start++ {
		single, err := result.OriginalRunes(start, start+1)
		if err != nil {
			t.Fatalf("%q: OriginalRunes(%d, %d): %v", input, start, start+1, err)
		}
		if single.Start < previous.Start || single.End < previous.End {
			t.Fatalf("%q: mapping not monotone at %d: %v after %v", input, start, single, previous)
		}
		previous = single
		for end := start + 1; end <= len(normalizedRunes) && end <= start+8; end++ {
			span, err := result.OriginalRunes(start, end)
			if err != nil {
				t.Fatalf("%q: OriginalRunes(%d, %d): %v", input, start, end, err)
			}
			if span.Start < 0 || span.Start >= span.End || span.End > len(originalRunes) {
				t.Fatalf("%q: OriginalRunes(%d, %d) = %v out of bounds", input, start, end, span)
			}
			if !breaks[span.Start] || !breaks[span.End] {
				t.Fatalf("%q: OriginalRunes(%d, %d) = %v splits a grapheme cluster", input, start, end, span)
			}
			// Coverage: normalizing the mapped original slice reproduces
			// the normalized range, except for a Stream-Safe U+034F that
			// only exists because of the surrounding text.
			mapped := withoutCGJ(Normalize(string(originalRunes[span.Start:span.End])).Text())
			if want := withoutCGJ(string(normalizedRunes[start:end])); !strings.Contains(mapped, want) {
				t.Fatalf("%q: OriginalRunes(%d, %d) = %v normalizes to %q, missing %q", input, start, end, span, mapped, want)
			}
			bytes, err := result.OriginalBytes(runeByteOffsets[start], runeByteOffsets[end])
			if err != nil {
				t.Fatalf("%q: OriginalBytes: %v", input, err)
			}
			if bytes != (Span{originalByteOffsets[span.Start], originalByteOffsets[span.End]}) {
				t.Fatalf("%q: OriginalBytes(%d, %d) = %v, rune span %v", input, runeByteOffsets[start], runeByteOffsets[end], bytes, span)
			}
		}
	}
}
