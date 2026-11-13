# ADR 0011: HTTP evaluation harness

## Status

Accepted

## Context

The detectors are heuristic (regular expressions and word lists). Their quality
changes whenever patterns, normalization (L4) or policies change, but nothing
measured it: unit tests pin individual rules, not precision, recall or false
positive rate. Operators and later lots need a number per detector that comes
from the same path a client uses, so that policy wiring, request limits and
response shaping are part of what is measured.

The archived Python implementation had a benchmark tied to its internals; copying
that design would couple the measurement to the code under test, so a refactor of
`internal/` could silently change both the detector and its yardstick.

Public datasets (BIPIA, AgentDojo, Presidio) are useful reference material but
carry licenses, are large, may contain realistic personal data, and do not label
the same thing as our detectors.

## Decision

### An independent command

`cmd/guardrail-eval` calls only the documented HTTP API (ADR 0005, 0006, 0007)
and imports nothing from `internal/`. Its packages (`cmd/guardrail-eval/eval`)
define their own request/response structs, so a contract change breaks the
harness visibly instead of being absorbed by a shared type.

Two modes cover the two public surfaces:

- `annotate` posts to `POST /v1/guardrails/{policy}` and reads `findings[].detector`.
  This measures detection independently of the policy action.
- `enforce` posts to the single-detector `/scan/*` routes and reads `decision`.
  This measures what a caller is actually told.

Requests are sequential, with a per-request timeout, an optional overall
timeout, context cancellation (`SIGINT`/`SIGTERM`), a bounded response body and
disabled redirects. Transport errors, non-2xx statuses, oversized or malformed
responses and payload-limit blocks are request errors, counted apart from
detection outcomes; the run aborts after N consecutive errors (default 5) so a
dead or unauthorized target does not take minutes to report. The API key comes
from the environment or a file, never from an argument, and is never printed.

### Versioned local contracts

- Corpus format v1: JSON Lines, a header plus cases with explicit per-detector
  boolean labels, language, input type and tags. Strict decoding, line-numbered
  errors, canonical writer.
- Report format v1: deterministic JSON (no timestamps), `report_version`, and a
  per-corpus section with per-detector counts and metrics plus breakdowns by
  language and tag, micro and macro aggregates, request errors and warnings.

Metrics with a zero denominator are reported as `{"value": 0, "defined": false}`
and shown as `n/a`: no `NaN`, no silent `0` or `1`. Micro aggregation sums
confusion matrices; macro aggregation averages only the detectors where the
metric is defined.

Corpora are never pooled. Each has its own detectors and aggregates because
labels from different sources are not equivalent.

### Corpus and loaders

`tests/eval/corpus/guardrail-serve-original-v1.jsonl` is a small original FR/EN
corpus with positives and negatives for the three detectors and no real secrets.
Labels state expected behaviour; known false positives and the English-only
injection patterns show up in the metrics and are not corrected by changing the
detectors or the labels. A change to the corpus is a new versioned file.

`tests/eval/loaders` converts BIPIA, AgentDojo and Presidio only when asked,
from a local file or from an HTTPS URL pinned to a commit and a SHA-256. There is
no automatic download, nothing fetched in tests or CI, output is restricted to a
git-ignored `.agent-tmp/` directory, and the imported header records the source
and the semantic gap (record-level labels, positives only, unmapped entity
types). Imported results are explicitly not comparable with the benchmarks' own
scores.

### Out of scope

The command never fails a run because of a metric, and no CI workflow uses it
yet. Regression thresholds and the workflow on fixtures belong to L7b, which
consumes the report JSON. Concurrency stays sequential because the service
defaults to two concurrent requests (ADR 0006).

## Alternatives considered

- Reuse the service's domain types in the harness: shorter code, but a contract
  change would be absorbed by both sides and hidden. Rejected.
- Evaluate detectors in-process as a Go benchmark: skips routing, policy wiring,
  limits and serialization, which are part of the product. Kept as unit tests only.
- Pool all corpora into one confusion matrix: yields a single headline number
  that mixes incompatible label semantics. Rejected.
- Report `NaN`, or `0`, for undefined ratios: `NaN` is not valid JSON and `0`
  reads as a result. Rejected for an explicit `defined` flag.
- Vendor the public datasets or download them on demand: license, size and
  privacy concerns, plus non-reproducible CI. Rejected for explicit pinned import.
- Pass the API key as a flag: leaks through process lists and shell history.
  Rejected for environment or file.

## Consequences

- Positives: reproducible per-detector precision/recall/FPR measured through the
  public API; a stable JSON contract for regression gates; honest reporting of
  request failures and undefined metrics; no new dependency.
- Negatives: the harness duplicates a few wire structs and must follow API
  changes; corpus labels are a judgement call that needs review; the small
  corpus gives wide confidence intervals, so single-case swings are normal.
- Risks: imported public data may contain sensitive-looking content, mitigated by
  the git-ignored destination and the "do not commit" notice; a service that
  rate-limits evaluation traffic produces request errors instead of metrics,
  mitigated by the sequential client and the consecutive-error abort.
