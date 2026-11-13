# ADR 0008: Text normalization with original offsets, and identifier validators

## Status

Accepted

## Context

Deterministic detectors are easy to evade with compatibility characters
(fullwidth letters, ligatures), decomposed accents, and invisible characters
(zero-width spaces, bidirectional overrides) inserted inside keywords or
identifiers. The French PII and injection lot (L4b) needs to scan a normalized
view of each text, and to confirm candidate identifiers with checksums to keep
false positives low. ADR 0007 fixes the reporting contract: detectors return
byte offsets on rune boundaries of the original text, findings carry rune
offsets of the original text, and masking rewrites original bytes. A
normalized view is therefore only usable with an offset map back to the
original text.

## Decision

Add two leaf packages with no dependency on HTTP, policy, detectors, storage,
or providers. This lot does not register them anywhere; L4b wires them.

### `internal/textnorm`

- `Normalize(text)` decodes runes like a Go `range` loop, strips a closed list
  of invisible formatting and bidirectional controls (`IsStripped`), then
  applies NFKC with `golang.org/x/text/unicode/norm`. Stripping comes first so
  split characters compose again; a test over every code point proves NFKC
  cannot reintroduce a stripped rune. The output equals `norm.NFKC.String` of
  the stripped text, Stream-Safe U+034F included, and is idempotent.
- The offset map is built per normalization segment: unchanged segments map
  rune for rune; every rune of a rewritten segment maps to all the original
  runes of that segment. Ranges are then widened to whole extended grapheme
  clusters of the original text (UAX #29, Unicode 15.0.0, the version of the
  Go standard library and x/text in this module). The Unicode data files are
  embedded and the official conformance suite runs in the unit tests.
- `OriginalBytes(start, end)` maps a non-empty normalized byte range (as
  returned by `regexp`) to original byte offsets on rune boundaries, which is
  what `domain.Detection` expects. `OriginalRunes` does the same in runes.
  The original range covers every contributing original rune, never splits an
  original grapheme cluster, is bounded by the original text, and is monotone
  in the normalized position. Edge stripped runes are excluded; stripped runes
  inside the range are included.

For L4b this means: run detectors on `Text()`, convert each match with
`OriginalBytes`, and return those offsets as the `Detection`; the policy
engine and finding contract stay unchanged, masking replaces the widened
original span, and two matches that are disjoint in the normalized text may
map to overlapping original spans (the engine already merges overlapping
masks). Inputs with invalid UTF-8 can yield an original offset on a stray
continuation byte, which the engine rejects; L4b must decide how such texts
are scanned.

### `internal/validators`

Pure functions return `Result{Valid, Reason}` with a typed `Reason`, and a
`Kind` enum with `ParseKind` for future configuration: payment cards (Luhn,
12-19 digits), IBAN (SWIFT IBAN Registry release 101 lengths and BBAN
structures, check digits 02-98, MOD 97-10), French NIR (structure, key
complement to 97, 2A/2B as 19/18, provisional numbers reported through
`NIRResult.Status`), and SIREN/SIRET (Luhn, INSEE La Poste exception). One
separator rule applies everywhere: ASCII space and hyphen between significant
characters. Values made of one repeated digit, which pass Luhn or MOD 97, are
rejected as trivial. Package READMEs list the rules and their primary sources.

## Alternatives considered

- Use NFKC alone and map offsets by re-normalizing prefixes: quadratic and
  still ambiguous for expansions. Rejected.
- Use `norm.Iter` segments: its position does not advance for every returned
  segment (decompositions are emitted in pieces), so segments cannot be paired
  with inputs reliably. Rejected for `QuickSpan` plus `NextBoundary`.
- Map without grapheme widening: a mask could cut an emoji ZWJ sequence or a
  base letter from its combining marks. Rejected.
- Add a grapheme segmentation library (for example rivo/uniseg): a new
  dependency for one function, with its own Unicode version to keep aligned.
  Rejected for the embedded UCD tables and conformance test.
- Strip every default-ignorable code point: also removes variation selectors
  and tag characters that L4b may want to detect explicitly. Deferred.

## Consequences

- Positives: detectors can match evasive text and still report exact original
  spans without any change to the policy engine or the findings contract;
  checksum confirmation is shared and documented.
- Negatives: about 200 KB of Unicode data is embedded in the binary;
  `golang.org/x/text` (already an indirect dependency through huma) becomes a
  direct dependency, pinned to v0.41.0, the latest release that does not raise
  the module's `go 1.26` directive.
- Risks: when Go or x/text change Unicode version, a unit test fails until the
  embedded data is refreshed; normalized ranges are covers rather than exact
  inverses, so masks can be wider than the matched text when a single
  original character expands.
