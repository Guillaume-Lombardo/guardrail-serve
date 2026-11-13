# ADR 0016: Optional semantic policy detector

Status: Accepted

## Context

L6a provides a validated HTTP implementation of `semantic.PromptInjectionDetector`
with aggregate assessments, chunking, bounded responses and typed failures. L3
policies consume per-text `domain.Detector` spans. The default service must remain
offline and deterministic. Domain interfaces must not acquire HTTP dependencies.

## Decision

Register `semantic_prompt_injection` only when static `SEMANTIC_ENABLED=true`.
The app composes the existing HTTP client with a new per-text policy adapter.
Configuration is validated without network access; an unknown or disabled detector
referenced by a policy fails startup. Embedded policies never reference it.

Both input and output stages are supported. One assessment is requested for each
original text; L6a retains sole ownership of chunking, score validation and timeout.
The assessment maximum belongs to that one text. A trigger emits one finding with
byte span `[0,len(original))`, projected by the engine into original rune offsets.
No chunk locality is inferred. Rule `semantic_classification`, type
`PROMPT_INJECTION` and blocking reason are fixed. Only the score enters findings;
provider reasons, model names and metadata are discarded.

Fail-closed typed errors flow through the existing policy error to HTTP 502 with
`Guardrail execution failed.`. LiteLLM must configure its own fail-closed behavior
for non-2xx responses. Fail-open may return NONE but emits a structured warning
with fixed detector/failure-mode fields on each degraded per-text evaluation.
L8b observation remains active: clean (including fail-open), match and error are
measured by the unchanged engine. The warning distinguishes degradation from a
healthy clean result. Caller cancellation always wins, including after assessment.

The domain contract now permits optional I/O without exposing provider types;
deterministic implementations retain their existing guarantees. No HTTP dependency
is introduced into the policy engine. Legacy semantic Guardrail remains unchanged.

## Consequences and limits

This is classification, not localization. Whole-text mask actions would replace
the entire original text; examples use block/annotate instead. Detect mode reports
findings but leaves texts and applied decision unchanged. Strict LiteLLM responses
remain action, optional blocked_reason, texts; no opaque degradation fields.

No classifier, model download, Python runtime, CGO or weights are required by the
Go binary. Operators own sidecar compatibility, calibration, availability, model
access and license compliance. Chunking is a rune heuristic, not tokenization;
long inputs can hit the existing bounded chunk limit. Each text has its own
client timeout; runtime deadlines still bound the incoming request. See README
for the sidecar wire contract, supported-image caveat and primary references.
