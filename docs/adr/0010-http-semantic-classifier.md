# ADR 0010: HTTP semantic classifier core

## Status

Accepted

## Context

ADR 0003 introduced `semantic.PromptInjectionDetector` and a guardrail that
consumes it, without any provider. The planned first provider is a small
prompt-injection classifier (Llama Prompt Guard 2, 22M or 86M parameters)
that must not run inside the Go process: the service stays CGO-free, ships no
weights and keeps deterministic guardrails working without the model.

Prompt Guard 2 has a 512-token window and its card asks callers to split
longer inputs. Sidecars exist in two shapes: a thin custom service and
Hugging Face Text Embeddings Inference (TEI), whose `/predict` endpoint has a
subtle batch format (a bare list of two strings is a text pair). The detector
interface returns `(assessment, error)`, so a provider failure needs an
explicit meaning (fail-open or fail-closed) instead of an accidental one.

This change delivers only the independent core. Policy wiring, configuration
and environment variables follow in a separate change.

## Decision

- New package `internal/semantic/httpclassifier` implements
  `semantic.PromptInjectionDetector`. It imports only the standard library and
  `internal/semantic`; the existing semantic and guardrail code is unchanged
  and nothing registers the package at runtime yet.
- Configuration is a Go struct passed to `New`; there is no environment
  access. Format and failure mode are typed enums with `Parse*` functions.
  `Format`, `Threshold`, `Timeout`, `URL` and `FailureMode` are mandatory,
  so there is no implicit fail-open and no implicit endpoint.
- Two explicit formats: `scores` (`{texts}` → `{scores}`) and `tei_predict`
  (TEI `/predict`, batch form `{"inputs": [[t1], [t2]]}`, response array of
  `{label, score}` arrays). Labels counted as malicious are configurable
  (default `MALICIOUS`); a response row without such a label is an error.
  Contracts and sources are documented in the package README.
- Texts are chunked into rune-aligned windows (default 510 runes, overlap 64)
  under a conservative heuristic of about one token per rune, because no
  tokenizer is available (not a guarantee; the sidecar rejects overflows
  explicitly). Whitespace and combining-sequence aware boundaries reduce
  mid-word cuts; overlap guarantees that short phrases are not lost at
  boundaries; every rune is covered. The score is the maximum over all
  chunks and texts, and all chunks are scored. Inputs above a chunk budget
  fail instead of being truncated.
- Failures are typed (`*Error` with a stable `Kind`, no input text, response
  content or URL in messages). `closed` returns the error. `open` returns a
  non-triggered assessment marked `classifier_degraded` with the failure
  kind. A cancelled caller context is always an error. The client timeout is
  a failure subject to the mode.
- Network behavior is minimal and bounded: one overall timeout, bounded
  response body, no retry, no redirect, no proxy, sequential batches.
- Threshold semantics match the existing guardrail: `score >= threshold`
  triggers, thresholds are in `(0, 1]`.

## Alternatives considered

- Embed the model in-process (CGO/ONNX): rejected, heavy and platform bound,
  and it would ship weights under the Llama license.
- Support only TEI: rejected, a thin custom sidecar is simpler to operate and
  to test, and the second format is small.
- Guess the wire format from the response: rejected, a misdetected shape could
  hide a wrong label mapping. The format is explicit.
- Treat a missing malicious label as score 0: rejected, a wrong label mapping
  would silently disable the guardrail.
- Fail-closed as a triggered assessment: rejected here, callers already map
  errors to HTTP 502 (ADR 0003) and a synthetic detection would be
  indistinguishable from a real one. The policy layer may map `*Error` to a
  block later.
- Let TEI truncate (`truncate: true`): rejected, silent truncation leaves part
  of the text unscanned.
- Stop at the first chunk over the threshold: rejected, the reported score
  would be partial and depend on batch order.
- Automatic retries: rejected, they multiply latency under the request
  timeout; retry policy belongs to the caller.

## Consequences

- Positives: the model runs and scales independently; deterministic
  guardrails are unaffected; failure behavior is explicit and testable;
  complete coverage of long inputs; no new dependency.
- Negatives: the one-token-per-rune estimate over-splits ordinary prose
  (about four times more calls than a real tokenizer would need); a
  sidecar hop adds latency and an availability dependency.
- Risks: fail-open lets an attacker who can degrade the sidecar bypass the
  detector, so wiring must expose `classifier_degraded` and default to
  closed; a misconfigured label list fails loudly rather than silently;
  operators carry the Llama license obligations for the weights; no sidecar
  authentication yet, to be decided with the wiring change.
