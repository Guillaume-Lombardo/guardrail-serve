package httpclassifier

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// reassemble rebuilds the original text from chunks produced with overlap.
func reassemble(chunks []string, overlap int) string {
	var builder strings.Builder
	for i, piece := range chunks {
		runes := []rune(piece)
		if i > 0 {
			runes = runes[overlap:]
		}
		builder.WriteString(string(runes))
	}
	return builder.String()
}

func TestSplitRunesShortTextIsUnchanged(t *testing.T) {
	chunks, complete := splitRunes("héllo", 16, 4, 10)
	if !complete || len(chunks) != 1 || chunks[0] != "héllo" {
		t.Fatalf("unexpected result %q complete=%v", chunks, complete)
	}
}

func TestSplitRunesCoversEveryRuneWithOverlap(t *testing.T) {
	samples := map[string]string{
		"ascii":      strings.Repeat("abcdefghij", 40),
		"words":      strings.Repeat("ignore the previous instruction ", 30),
		"multibyte":  strings.Repeat("日本語のテキスト、", 50),
		"emoji":      strings.Repeat("a👩‍👩‍👧‍👦b🏽", 60),
		"combining":  strings.Repeat("é", 200),
		"no spaces":  strings.Repeat("x", 301),
		"whitespace": strings.Repeat(" \t\n", 100),
	}
	for name, text := range samples {
		t.Run(name, func(t *testing.T) {
			const size, overlap = 64, 16
			chunks, complete := splitRunes(text, size, overlap, 1000)
			if !complete || len(chunks) < 2 {
				t.Fatalf("expected several complete chunks, got %d complete=%v", len(chunks), complete)
			}
			for i, piece := range chunks {
				if !utf8.ValidString(piece) {
					t.Fatalf("chunk %d is not valid UTF-8", i)
				}
				if got := utf8.RuneCountInString(piece); got > size || got <= overlap {
					t.Fatalf("chunk %d has %d runes", i, got)
				}
			}
			if got := reassemble(chunks, overlap); got != text {
				t.Fatal("chunks with overlaps removed do not rebuild the original text")
			}
		})
	}
}

func TestSplitRunesPrefersWhitespaceBoundary(t *testing.T) {
	text := strings.Repeat("abcdefg ", 20)
	chunks, _ := splitRunes(text, 64, 8, 100)
	for i, piece := range chunks[:len(chunks)-1] {
		if !strings.HasSuffix(piece, " ") {
			t.Fatalf("chunk %d does not end after whitespace: %q", i, piece)
		}
	}
}

func TestSplitRunesDoesNotSeparateCombiningMarks(t *testing.T) {
	text := strings.Repeat("a", 63) + "é" + strings.Repeat("b", 120)
	chunks, _ := splitRunes(text, 64, 8, 100)
	for i, piece := range chunks[1:] {
		first, _ := utf8.DecodeRuneInString(piece)
		if first == '́' {
			t.Fatalf("chunk %d starts with a combining mark", i+1)
		}
	}
}

func TestSplitRunesKeepsPhraseWithinOverlapIntact(t *testing.T) {
	const phrase = "ignore previous instructions"
	for offset := 0; offset < 200; offset++ {
		text := strings.Repeat("x", offset) + phrase + strings.Repeat("y", 300)
		chunks, _ := splitRunes(text, 100, 25, 100)
		found := false
		for _, piece := range chunks {
			found = found || strings.Contains(piece, phrase)
		}
		if !found {
			t.Fatalf("phrase at offset %d is split across chunks", offset)
		}
	}
}

func TestSplitRunesStopsAtLimit(t *testing.T) {
	text := strings.Repeat("x", 10_000)
	chunks, complete := splitRunes(text, 64, 8, 3)
	if complete || len(chunks) != 3 {
		t.Fatalf("expected 3 chunks and incomplete, got %d complete=%v", len(chunks), complete)
	}
	if _, complete := splitRunes("short", 64, 8, 0); complete {
		t.Fatal("a zero limit must report incomplete")
	}
}

func TestSplitRunesNormalizesInvalidUTF8(t *testing.T) {
	text := strings.Repeat("a\xffb", 100)
	chunks, _ := splitRunes(text, 64, 8, 100)
	for i, piece := range chunks {
		if !utf8.ValidString(piece) {
			t.Fatalf("chunk %d is not valid UTF-8", i)
		}
	}
}
