# 0003 - Semantic guardrail adapter foundation

## Context

The repository intentionally started with deterministic guardrails only.

The next product step is to support richer semantic checks driven by external providers such as embedding services or LLM evaluators. Those integrations introduce runtime failures, latency, and provider-specific contracts that deterministic guardrails do not have today.

Before wiring any real provider, the service needs internal contracts that:

- keep semantic logic decoupled from HTTP
- allow provider-backed guardrails to surface execution failures explicitly
- remain optional so the base runtime still works without external dependencies

## Decision

Extend the internal `Guardrail` contract so execution returns both a `Result` and an `error`.

Introduce provider-neutral semantic interfaces in a dedicated package and implement a first semantic prompt-injection guardrail behind an injected detector interface.

Map guardrail execution failures to a stable HTTP `502 Bad Gateway` response with a generic error body while logging the underlying error through request-scoped observability.

Do not expose a production semantic route or a concrete provider integration in this slice. Keep the change focused on internal contracts and testable foundations.

## Alternatives considered

- Keep the current `Guardrail` interface error-free and encode provider failures as synthetic decisions.
- Add a provider integration first and defer internal contract cleanup until later.
- Couple semantic evaluation directly into the HTTP handler layer.

## Consequences

- Positives:
  - external-boundary failures can now be represented explicitly
  - semantic adapters stay injectable and provider-agnostic
  - the deterministic base runtime remains dependency-light
- Negatives:
  - the guardrail contract becomes slightly heavier because all implementations now return `(Result, error)`
  - HTTP behavior for provider-backed failures is defined before a real provider exists
- Risks:
  - future provider integrations may need richer error taxonomy than a single HTTP `502`
  - exposing a semantic route later still requires careful product and API design
