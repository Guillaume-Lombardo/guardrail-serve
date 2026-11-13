# textnorm

Deterministic text normalization with an offset map back to the original text.
The package has no dependency on HTTP, policy, detectors, or providers; it only
uses the standard library and `golang.org/x/text/unicode/norm`.

```go
result := textnorm.Normalize(original)
scanned := result.Text()

// A detector matches on the normalized text (regexp byte offsets)...
loc := pattern.FindStringIndex(scanned)
// ...and reports the original bytes, ready for domain.Detection.
span, err := result.OriginalBytes(loc[0], loc[1])
```

## Pipeline

1. **Decode.** The input is read as a Go `range` loop reads a string. Each
   invalid UTF-8 byte is one original rune and becomes U+FFFD in the output.
   "Original rune index" always means the index in that sequence, the same
   counting used by `domain.Finding`.
2. **Strip.** Exactly these code points are removed (`IsStripped`):
   - invisible formatting: U+00AD SOFT HYPHEN, U+180E MONGOLIAN VOWEL
     SEPARATOR, U+200B ZERO WIDTH SPACE, U+200C ZERO WIDTH NON-JOINER,
     U+200D ZERO WIDTH JOINER, U+2060 WORD JOINER, U+2061..U+2064 invisible
     mathematical operators, U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM);
   - bidirectional controls: U+061C ARABIC LETTER MARK, U+200E LEFT-TO-RIGHT
     MARK, U+200F RIGHT-TO-LEFT MARK, U+202A..U+202E embeddings and overrides,
     U+2066..U+2069 isolates.

   Nothing else is removed: letters, digits, and marks of every script are
   kept, and so are other default-ignorable code points such as variation
   selectors and tag characters. Removing ZWJ and ZWNJ can change how some
   scripts (for example Persian or Devanagari) or emoji sequences render, but no
   letter is lost.
3. **NFKC.** Stripping happens first so that text split by an invisible
   character composes again (`e`, ZWSP, U+0301 becomes `é`). A unit test checks
   every code point to prove that NFKC never produces a stripped rune, so the
   output never contains one. The output equals
   `norm.NFKC.String(stripped)`, including the U+034F COMBINING GRAPHEME JOINER
   that x/text inserts in runs of more than 30 non-starters (Stream-Safe Text
   Format), and normalization is idempotent.

## Offset contract

`OriginalRunes(start, end)` takes a non-empty normalized rune range and
`OriginalBytes(start, end)` a non-empty normalized byte range on rune
boundaries (the form returned by `regexp`). Both return a half-open original
range `[Start, End)`, in runes or bytes. Empty, reversed, out-of-range, or
rune-splitting requests return `ErrInvalidRange`.

The mapping is built per normalization segment (a starter and the
non-starters that may combine with it, cut at x/text boundaries):

- An unchanged segment maps rune for rune.
- In a rewritten segment, every output rune maps to all the original runes of
  that segment, including runes stripped inside it. So the `f` of `fi` produced
  by the ligature `ﬁ` maps to the whole ligature, and `é` produced by `e` +
  U+0301 maps to both runes.
- A Stream-Safe U+034F maps to the original rune it precedes.
- The range is then widened to whole extended grapheme clusters of the original
  text (UAX #29 rules for Unicode 15.0.0), so a match never splits a
  contributing grapheme: `👩` matched in `👩` ZWJ `💻` maps to the whole
  ZWJ sequence, and one regional indicator maps to its flag pair.

Guarantees, all covered by tests and a fuzz target:

- **Coverage.** The original range contains every original rune that produced
  the normalized range; normalizing it again yields text that contains the
  normalized range (ignoring a Stream-Safe U+034F).
- **Grapheme alignment.** `Start` and `End` are grapheme cluster boundaries of
  the original text.
- **Monotone and bounded.** For single-rune ranges, `Start` and `End` never
  decrease as the normalized index grows, and
  `0 <= Start < End <= OriginalLen()`.
- **Consistency.** `OriginalBytes` returns the byte offsets of the same runes as
  `OriginalRunes`.

### Ambiguities and choices

- Stripped runes at the edges of a match are not part of the original range;
  stripped runes strictly inside it are (`se`, ZWSP, `cret` matched as `secret`
  covers the ZWSP). A stripped rune that belongs to the same grapheme cluster
  as a contributing rune, such as a ZWJ inside an emoji sequence, is included
  by grapheme widening.
- Many-to-one and one-to-many rewrites cannot be split: a match on part of an
  expansion (`k` of `kg` from `㎏`) maps to the whole source character, and a
  match on part of a composed segment maps to the whole segment. The mapping is
  therefore a cover, not a bijection, and adjacent normalized ranges may map to
  overlapping original ranges.
- Grapheme clusters follow Unicode 15.0.0, the version of the Go standard
  library and x/text in this module. Unicode 15.1 rule GB9c (Indic conjuncts)
  is not applied, so a conjunct such as `क्ष` is two clusters.
- Invalid UTF-8 bytes map one to one with their U+FFFD replacement. A stray
  continuation byte is a valid rune position for this package but not a UTF-8
  rune start; callers that require rune-start offsets (the policy engine does)
  must handle such inputs.

## Unicode data

`ucd/` embeds `GraphemeBreakProperty-15.0.0.txt` and `emoji-data-15.0.0.txt`
from the Unicode Character Database (trailing whitespace removed), and
`testdata/GraphemeBreakTest-15.0.0.txt` is the official conformance suite run by
the unit tests. A test fails when the Go `unicode` package or x/text move to
another Unicode version: refresh the three files from
`https://www.unicode.org/Public/<version>/ucd/` and update
`graphemeUnicodeVersion`. Unicode data files are distributed under the Unicode
License (https://www.unicode.org/license.txt).

## Cost

`Normalize` is linear in the input. It allocates a few integers per original
and per normalized rune; NFKC expands one rune into at most 18 (U+FDFA), which
bounds the normalized side for texts already limited by `MAX_TEXT_CHARS`.
