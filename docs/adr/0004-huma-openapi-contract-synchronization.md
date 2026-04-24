# ADR 0004: Huma For HTTP Contract Synchronization

## Status

Accepted

## Context

The service exposes a public HTTP API and now needs a stronger guarantee that the documented OpenAPI contract stays synchronized with the actual Go request and response types.

The previous `net/http` route layer kept the transport simple, but OpenAPI generation and interactive documentation were not first-class runtime outputs. This created a risk of contract drift between code, generated Swagger/OpenAPI artifacts, and future client integrations.

The target user experience is FastAPI-like:

- interactive docs on `/docs`
- generated OpenAPI JSON on `/openapi.json`
- generated OpenAPI YAML on `/openapi.yaml`

The repository constraints still apply:

- keep guardrail logic decoupled from HTTP/framework specifics
- keep external contracts explicit and versionable
- keep runtime behavior deterministic where guardrails are deterministic

## Decision

Adopt `github.com/danielgtaylor/huma/v2` as the canonical public HTTP contract layer.

Implementation rules:

- register public routes as `huma` operations
- define canonical HTTP request/response schema structs in Go and let `huma` generate OpenAPI from them
- expose Swagger UI on `/docs`
- expose generated OpenAPI on `/openapi.json` and `/openapi.yaml`
- keep guardrail execution/orchestration in internal helpers, separate from the `huma` registration layer
- preserve simple JSON error bodies for the service instead of adopting Huma's default RFC 9457 problem payloads verbatim

## Consequences

### Positive

- OpenAPI is generated directly from registered handlers and schema types
- interactive documentation is served by the application itself
- contract drift risk is reduced significantly
- the project gets a clearer single source of truth for public HTTP payloads

### Negative

- the transport layer now depends on `huma`
- some low-level HTTP behavior is influenced by the framework unless explicitly overridden
- integration tests must validate docs/spec routes in addition to business routes

## Alternatives Considered

### Keep ad hoc `net/http` handlers and generate OpenAPI separately

Rejected because it leaves room for schema/code divergence and adds another artifact pipeline to maintain.

### Hand-write Swagger/OpenAPI files

Rejected because it makes synchronization a manual discipline instead of an enforced property of the codebase.

## Follow-up

- keep request/response schema definitions centralized in the HTTP package
- document any future public contract changes directly in the `huma` operation/types layer
- add tests for docs/spec exposure whenever public HTTP wiring changes
