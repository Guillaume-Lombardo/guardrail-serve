package textnorm

import (
	"fmt"
	"slices"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Folded is a matching-only view of a normalized text. It is never returned
// to callers as text and never replaces Result.Text: detectors that opt in
// match on it and report original spans through OriginalBytes.
//
// Fold applies, to each rune of the normalized text:
//
//  1. apostrophe variants (U+2018, U+2019, U+02BC, U+FF07 after NFKC) become
//     U+0027;
//  2. simple lowercase mapping (unicode.ToLower);
//  3. canonical decomposition (NFD) with every nonspacing mark (Mn) removed,
//     so "é" and "e" + U+0301 both fold to "e";
//  4. a closed table of Cyrillic and Greek letters that look like Latin
//     letters (homoglyphs), for example Cyrillic "о" to "o";
//  5. digits used as letters ("0" o, "1" i, "3" e, "4" a, "5" s, "7" t) when
//     an adjacent normalized rune is a letter, so "pr3cedentes" folds to
//     "precedentes" while "14 h" is unchanged.
//
// Then runs of at least four single letters separated only by spacing
// characters ("i g n o r e") are joined: a one-rune gap is removed and a
// longer gap becomes one space, so "i g n o r e  l e s" folds to "ignore les".
//
// Every folded rune maps to the normalized rune it came from, so a folded
// range maps to a contiguous normalized range and then, through the Result,
// to whole original grapheme clusters.
type Folded struct {
	base *Result
	text string
	// bytes[i] is the byte offset of folded rune i; the last entry is len(text).
	bytes []int
	// source[i] is the normalized rune index that produced folded rune i. It
	// is non-decreasing.
	source []int
}

// minSpacedRun is the number of single letters that makes a spaced-out word.
// Shorter runs ("y a", "à l") occur in ordinary French and stay unchanged.
const minSpacedRun = 4

// Fold returns the matching-only folded view of r.
func (r *Result) Fold() *Folded {
	normalized := []rune(r.text)
	var runes []rune
	var source []int
	for index, original := range normalized {
		for _, folded := range foldRune(normalized, index, original) {
			runes = append(runes, folded)
			source = append(source, index)
		}
	}
	runes, source = joinSpacedLetters(runes, source)
	f := &Folded{base: r, source: source}
	var text []byte
	for _, folded := range runes {
		f.bytes = append(f.bytes, len(text))
		text = utf8.AppendRune(text, folded)
	}
	f.bytes = append(f.bytes, len(text))
	f.text = string(text)
	return f
}

func foldRune(normalized []rune, index int, r rune) []rune {
	switch r {
	case '‘', '’', 'ʼ':
		return []rune{'\''}
	}
	if letter, ok := leetLetter(r); ok && adjacentLetter(normalized, index) {
		return []rune{letter}
	}
	var out []rune
	for _, decomposed := range norm.NFD.String(string(unicode.ToLower(r))) {
		if unicode.Is(unicode.Mn, decomposed) {
			continue
		}
		if latin, ok := homoglyphs[decomposed]; ok {
			decomposed = latin
		}
		out = append(out, decomposed)
	}
	return out
}

func leetLetter(r rune) (rune, bool) {
	switch r {
	case '0':
		return 'o', true
	case '1':
		return 'i', true
	case '3':
		return 'e', true
	case '4':
		return 'a', true
	case '5':
		return 's', true
	case '7':
		return 't', true
	}
	return 0, false
}

func adjacentLetter(normalized []rune, index int) bool {
	return index > 0 && unicode.IsLetter(normalized[index-1]) ||
		index+1 < len(normalized) && unicode.IsLetter(normalized[index+1])
}

// homoglyphs maps lowercase Cyrillic and Greek letters to the Latin letter
// they are commonly confused with. Uppercase lookalikes are covered because
// folding lowercases first. The table is closed and only used for matching.
var homoglyphs = map[rune]rune{
	// Cyrillic.
	'а': 'a', 'в': 'b', 'е': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o',
	'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i',
	'ј': 'j', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'һ': 'h', 'ү': 'y', 'ӏ': 'l',
	// Greek.
	'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
	'τ': 't', 'υ': 'u', 'χ': 'x',
	// Latin variants.
	'ı': 'i', 'ɑ': 'a', 'ɡ': 'g',
}

func isSpacing(r rune) bool {
	switch r {
	case ' ', '\t', '.', '-', '_', '*', '+', '·':
		return true
	}
	return false
}

// joinSpacedLetters joins runs of single letters separated by spacing.
func joinSpacedLetters(runes []rune, source []int) ([]rune, []int) {
	single := func(i int) bool {
		return unicode.IsLetter(runes[i]) &&
			(i == 0 || !unicode.IsLetter(runes[i-1]) && runes[i-1] != '\'') &&
			(i+1 == len(runes) || !unicode.IsLetter(runes[i+1]) && runes[i+1] != '\'')
	}
	// drop[i] removes rune i; space[i] replaces a gap starting at i by one space.
	drop := make([]bool, len(runes))
	for start := 0; start < len(runes); {
		if !single(start) {
			start++
			continue
		}
		letters := []int{start}
		next := start + 1
		for {
			gap := next
			for gap < len(runes) && isSpacing(runes[gap]) {
				gap++
			}
			if gap == next || gap == len(runes) || !single(gap) {
				break
			}
			letters = append(letters, gap)
			next = gap + 1
		}
		if len(letters) >= minSpacedRun {
			for k := 1; k < len(letters); k++ {
				from, to := letters[k-1]+1, letters[k]
				for i := from; i < to; i++ {
					drop[i] = true
				}
				if to-from > 1 {
					// A wider gap separates words: keep its first rune as a space.
					drop[from] = false
					runes[from] = ' '
				}
			}
		}
		start = letters[len(letters)-1] + 1
	}
	keptRunes, keptSource := runes[:0:0], source[:0:0]
	for i := range runes {
		if !drop[i] {
			keptRunes = append(keptRunes, runes[i])
			keptSource = append(keptSource, source[i])
		}
	}
	return keptRunes, keptSource
}

// Text returns the folded text, for matching only.
func (f *Folded) Text() string { return f.text }

// OriginalBytes maps the non-empty folded byte range [start, end), on rune
// boundaries of Text, to the original byte range covering every original
// rune that contributed to it, widened to whole original grapheme clusters.
func (f *Folded) OriginalBytes(start, end int) (Span, error) {
	runeStart, okStart := slices.BinarySearch(f.bytes, start)
	runeEnd, okEnd := slices.BinarySearch(f.bytes, end)
	if !okStart || !okEnd || runeStart >= runeEnd {
		return Span{}, fmt.Errorf("%w: folded byte range [%d,%d) over %d bytes", ErrInvalidRange, start, end, len(f.text))
	}
	first, last := f.source[runeStart], f.source[runeEnd-1]
	return f.base.OriginalBytes(f.base.normBytes[first], f.base.normBytes[last+1])
}
