# ADR 0015: Offline evaluation regression gate

## Status

Accepted

## Context

ADR 0011 established the HTTP evaluator and original 83-case FR/EN corpus.
L4b improved French/PII detection. L7b must prevent regressions while exposing
remaining heuristic limitations, without modifying detectors or corpus labels.
A total score can hide a newly broken case behind an improvement elsewhere.

## Decision

A separate Evaluation workflow runs `scripts/eval-offline.sh`. Go is provisioned
from `go.mod`; modules are provisioned before evaluation. The evaluation phase
sets `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`. It imports no public
datasets, downloads no models and calls no LLM. This is an offline evaluation,
not an air-gapped CI bootstrap (checkout, setup, modules and artifact upload
still require the CI infrastructure).

The test harness starts the real service handler with explicit default config
on an OS-assigned loopback listener. `httptest.NewServer` starts synchronously;
there is no readiness polling or fixed-port reservation race. The test closes
the server using cleanup, bounds the run to 30 seconds and requests to one
second. No service subprocess is needed, so no shell process trap is needed.
Only the harness bootstrap imports service packages; the evaluator and comparator
use the evaluator's independent HTTP types. Measurement reuses the CLI runner,
one single-case corpus at a time, retaining observations without changing the
version 1 CLI report contract.

The versioned snapshot identifies one corpus by name and SHA-256 and pins
`annotate`/`audit`. It includes per-case detection booleans, counts and precision,
recall and FPR by detector and language (plus detector totals), and a list of
known FP/FN case IDs. It contains no source texts, credentials or target URL.
Snapshots from different corpora are never pooled. Missing cases/labels, changed
identity, inconsistent summaries and request errors fail the gate. Transport
errors never become negative classifications.

Thresholds are exactly the measured baseline: precision and recall may not
fall; FPR may not rise. Every previously correct label must remain correct,
even if improvements compensate in aggregate. A baseline metric with zero
denominator is explicitly undefined (`value: 0, defined: false`) and imposes no
numeric threshold; a defined baseline metric must remain defined. No rounding
is used for comparisons. Undefined current precision therefore cannot hide
lost true positives.

Baseline refresh is explicit and first compares the new measurement against
the old baseline. It cannot relax gates. Future L5b/L6b improvements can tighten
the baseline after reviewed evidence (old/new counts, corrected case IDs,
passing old gate). The original corpus stays immutable; changing it requires
a new corpus version and a separate baseline, with review of coverage.

## Consequences

The initial baseline at f3950e90e22a3e8bcb20443ae33f16591d618a13 has 17
misclassified labels, retained in `known_failures` rather than relabelled.
Small fixtures are a regression signal, not a statistical quality guarantee.
A measured improvement is accepted without a baseline update, but must be
explicitly refreshed to protect its newly corrected cases in future runs.

A subprocess test injects missing detections through HTTP and proves the same
test-process boundary used by CI exits nonzero. Comparator tests cover a
compensating improvement with identical aggregate scores. CI uploads the
text-free current snapshot and gate verdict even on comparator failure.
An evaluation request failure fails immediately; no partial snapshot is
published as a valid measurement.

## Alternatives

- Aggregate-only thresholds: rejected because they permit case swaps.
- Perfect detector accuracy: rejected because known limitations are honest data.
- Calling domain detectors directly: rejected because it bypasses the API.
- Extending CLI report v1: unnecessary; the test harness can use the same runner.
