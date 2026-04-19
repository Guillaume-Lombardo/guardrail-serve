# 0002 - Request context and structured logging

## Context

The service now needs better operational observability during contract hardening.

When a request is rejected, blocked, redacted, or succeeds normally, operators need enough context in logs to understand what happened without reconstructing the flow from multiple unrelated lines.

The repository also prefers stdlib-first choices and clear boundaries. Any observability addition should stay lightweight, avoid forcing third-party logging stacks, and preserve a path for future adapters that may depend on request-scoped context.

## Decision

Use a request-scoped context that is created at the HTTP entrypoint, attached to `context.Context`, and propagated through handler execution and guardrail evaluation.

Use the Go standard library `log/slog` for structured logging with a configurable output format:

- `human` for local/operator-friendly text logs
- `json` for machine-readable export and downstream processing

Emit one structured request log at the end of each HTTP request with contextual fields such as:

- request id
- method and path
- guardrail name
- input scope
- decision
- status code
- duration
- relevant error detail when present

Return the request id to clients through the `X-Request-ID` response header, reusing the inbound header value when provided.

## Alternatives considered

- Keep the current unstructured `log` package usage and only add ad hoc fields in messages.
- Introduce a third-party logging stack to mimic Python `structlog` behavior more closely.
- Log only errors and skip structured success logs.

## Consequences

- Positives:
  - request handling now has a stable context carrier for future external-boundary work
  - logs become easier to filter, correlate, and export without adding new runtime dependencies
  - request ids are visible both in logs and client responses
- Negatives:
  - guardrail interfaces now carry `context.Context`, which increases boilerplate slightly
  - human-readable logs are `slog` text output rather than a custom `structlog` clone
- Risks:
  - log field growth may become noisy if additional context is added without discipline
  - future async/background work will need explicit propagation if it should share request correlation data
