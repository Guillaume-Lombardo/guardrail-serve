# ADR 0013: Normalized PII and injection detector integration

## Status

Accepted

## Decision

L4b wires the L4a packages into the shared regex detector only for `detect_pii`
and `prompt_injection`. Secrets and semantic detectors keep their existing
paths. Normalize once per detector invocation; match normalized byte offsets;
confirm PII candidates with `internal/validators`; convert accepted ranges with
`OriginalBytes` into `domain.Detection`. The existing engine converts original
bytes to finding runes and merges overlapping masks. No Unicode data,
dependency version, policy stages or transport contracts change.

YAML PII rules explicitly select a typed validator. Invalid configuration is
rejected at construction. French business/social identifiers require labels;
this avoids broad checksum-valid numeric-sequence false positives. Candidate
boundaries reject identifiers embedded in longer alphanumeric tokens. IPv4
suppresses immediately adjacent version context. Cards do not consume trailing
separators. French labeled identifiers take precedence over the generic card
candidate even when a failed NIR checksum happens to satisfy Luhn.

## Invalid input

The library rejects invalid UTF-8 before normalization, returning an error and
no partial detections. It also rejects U+FFFD, including genuine U+FFFD, because
JSON decoding repairs malformed bytes and unpaired surrogates into that rune.
This conservative choice avoids silent loss of a match inside a damaged keyword
without modifying the decoder, admission or the standalone normalization core.
The existing detector-error response is HTTP 500, with no findings/texts and no
input values in errors. Consumers must treat this response as failed evaluation.
A future transport contract may introduce a specific 4xx invalid-text response.

Rejected: silently skip invalid offsets (could allow hostile text), repair the
string and return repaired offsets (violates the original-offset contract), or
remove replacement characters (changes meaning and hides malformed input).

## Consequences

Clean/annotated/detect-mode texts remain unchanged; only masked original spans
are rewritten. Grapheme widening can yield overlapping original ranges from
separate expansion matches; this is intentional and deterministic. Bounded
English/French regex heuristics cover the documented forms, not every paraphrase.
U+FFFD input is unavailable to policies using PII/injection. No new environment
variables or configuration bootstrap changes are needed.
