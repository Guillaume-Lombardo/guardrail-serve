# 0001 - Go guardrail service foundation

## Context

The repository started from a Python package template and contains an archived Python implementation of a guardrail API in `archive/bdf-guardrails`.

The target product is now a native Go service that preserves the useful HTTP contract of the archived service while improving latency, reducing runtime footprint, and keeping a clean path for future semantic guardrails based on embeddings or LLMs.

The first iteration must support:

- deterministic request/response guardrails
- `/scan/*` routes
- `/beta/litellm_basic_guardrail_api`
- the decision contract `NONE | BLOCKED | GUARDRAIL_INTERVENED`

The implementation must keep `archive/` out of active commit scope.

## Decision

Use a layered Go architecture with explicit separation between:

- domain contracts and guardrail result types
- built-in guardrail implementations
- configuration and resource loading
- HTTP transport and JSON schema handling
- application bootstrap

Adopt a stdlib-first stack for the first implementation:

- `net/http` for transport
- embedded YAML resources for default regex rule sets
- environment-driven configuration with small local parsing helpers
- in-process registry for built-in guardrails

Design the service so deterministic guardrails are part of the default binary, while embedding- and LLM-backed guardrails can be added later as optional adapters behind interfaces.

## Alternatives considered

- Use a full HTTP framework such as Gin, Echo, or Fiber.
- Port Python dependencies directly and maximize feature parity before simplifying.
- Build semantic-provider integration into the base runtime from day one.

## Consequences

- Positives:
  - smaller dependency surface and easier operational footprint
  - explicit boundaries between fast deterministic paths and future semantic adapters
  - straightforward testing with `net/http/httptest`
  - easier to embed default rule sets while allowing override paths
- Negatives:
  - more boilerplate than a higher-level framework
  - some Python behavior will be intentionally simplified in the first cut
- Risks:
  - semantic guardrails may require additional abstractions later
  - route and schema parity must be validated carefully during migration
