# guardrail-serve

Native Go service for serving LLM guardrails.

The public HTTP contract is exposed through `huma`, so the registered Go request/response types are the source of truth for the generated OpenAPI document and Swagger UI.

## Status

This repository is migrating from the archived Python reference implementation in `archive/python-reference` to a native Go implementation focused on lower latency, smaller images, and clearer operational boundaries.

`archive/` is reference material only and must never be committed as part of active delivery work.

## Current Target

The first Go implementation serves deterministic guardrails on:

- `/scan/secrets`
- `/scan/pii`
- `/scan/prompt-injection`
- `/beta/litellm_basic_guardrail_api`
- `/docs`
- `/openapi.json`
- `/openapi.yaml`

The decision contract is:

- `NONE`
- `BLOCKED`
- `GUARDRAIL_INTERVENED`

HTTP errors are returned as JSON with a `detail` field.
Guardrail execution failures are returned as HTTP `502` with the stable JSON detail `Guardrail execution failed.`.

Interactive Swagger UI is served on `/docs`.
Generated OpenAPI is served on `/openapi.json` and `/openapi.yaml`.
When `API_PREFIX` is configured, these routes are served under the same prefix.

### Route contracts

All scan requests require at least one `texts` entry; `input_type` defaults to
`request` and accepts `request` or `response`. `request_data` accepts arbitrary
metadata, including LiteLLM `user_api_key_*` values, without evaluating it.

`/scan/*` uses a strict schema: unknown fields and non-empty `images`, `tools`,
`tool_calls`, and `structured_messages` are rejected. Responses retain
`decision`, `texts`, `metadata`, and optional `reason`.

`/beta/litellm_basic_guardrail_api` implements the
[LiteLLM Generic Guardrail API](https://docs.litellm.ai/docs/adding_provider/generic_guardrail_api).
It accepts `litellm_call_id`, `litellm_trace_id`, `litellm_version`,
`request_headers`, and `additional_provider_specific_params`, and ignores unknown
fields. Metadata and forwarded headers are opaque: they do not select policies,
authenticate callers, or change guardrail settings.

The LiteLLM route accepts `images`, `tools`, `tool_calls`, and
`structured_messages` without evaluating or rewriting them. Only extracted
`texts` are scanned; callers must not treat this endpoint as image, tool, or
structured-message protection. Requests without text items remain invalid.

LiteLLM responses use `action` (`NONE`, `BLOCKED`, or `GUARDRAIL_INTERVENED`),
`blocked_reason` when blocked, and `texts` in the same order and count as input,
including unchanged entries when another entry is redacted. For example:

```json
{"action":"GUARDRAIL_INTERVENED","texts":["hello","password=[REDACTED]"]}
```

The LiteLLM response does not expose the internal scan `decision`/`metadata`
fields. A guardrail returning misaligned text items produces HTTP `502` rather
than an invalid rewrite.

Each request returns an `X-Request-ID` header. If the client provides `X-Request-ID`, the service reuses it for request correlation.

## Runtime configuration

`MAX_TEXT_ITEMS` (default `20`) limits text entries. `MAX_TEXT_CHARS` (default
`20000`) counts Unicode code points (runes) across all entries, including combining
marks separately. Invalid or non-positive text limits use these defaults.

Transport limits are independent of text limits:

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `HTTP_READ_HEADER_TIMEOUT` | `5s` | Time to read request headers |
| `HTTP_READ_TIMEOUT` | `15s` | Time to read the complete request, including its body |
| `HTTP_WRITE_TIMEOUT` | `30s` | Response write deadline |
| `HTTP_IDLE_TIMEOUT` | `60s` | Keep-alive idle deadline |
| `HTTP_SHUTDOWN_TIMEOUT` | `10s` | Graceful drain deadline after SIGTERM or SIGINT |
| `HTTP_MAX_BODY_BYTES` | `1048576` | Maximum encoded request body size in bytes |
| `GUARDRAIL_API_KEYS` | empty | Optional comma-separated API keys |

Timeouts accept positive Go durations such as `500ms` or `30s`; invalid,
non-positive or overflowing settings fail startup. The body limit must be a
positive integer from `1` to `1048576`, matching the HTTP decoder ceiling. Oversized requests return HTTP `413`,
including bodies with unknown content length. Body read failures return `400`.
On shutdown the server stops accepting connections, drains active requests, then
closes remaining connections when the deadline expires.

An unset or empty `GUARDRAIL_API_KEYS` preserves unauthenticated access. When set,
all routes (including docs and OpenAPI) require either `Authorization: Bearer <key>`
or `X-API-Key: <key>`. Only `GET <API_PREFIX>/health/` is exempt. Keys are trimmed
when loaded; empty comma-separated entries and whitespace inside keys fail startup.
Multiple credential headers, including using both header forms, are rejected with
`401`. Keys are hashed and compared in constant time across the whole configured
set, and never included in authentication errors or logs. Use TLS at the ingress
and provide keys through the environment, never a committed configuration file.

## Logging

Logging uses the Go stdlib `log/slog` stack.

- `LOG_FORMAT=human` emits readable text logs for local development and operator inspection
- `LOG_FORMAT=json` emits structured JSON logs for export pipelines and machine processing

Request logs include contextual fields such as request id, method, path, guardrail, input type, decision, status code, and duration.

## Development Workflow

```bash
gofmt -w .
go test ./...
go test ./tests/integration/...
go test ./tests/end2end/...
pre-commit run --all-files
```

## Project Layout

- `cmd/guardrail-serve`: application entrypoint
- `internal/app`: application wiring and HTTP server bootstrap
- `internal/domain`: guardrail contracts and core behaviors
- `internal/guardrails`: built-in guardrail implementations
- `internal/httpapi`: HTTP handlers, routes, request/response schemas
- `internal/config`: environment and runtime configuration
- `internal/resources`: embedded YAML rule sets and loading helpers
- `tests`: unit, integration, and end-to-end coverage
- `docs`: engineering guides and ADR records (`docs/README.md`)
- `skills`: AI helper skills for coding workflows
- `agent.md`: AI agent role, principles, and delivery contract
- `AGENTS.md`: operational guardrails and pre-PR checklist
- `plan.md`: collaborative planning workspace
- `SKILLS.md`: index of local skills and when to apply them

## GitHub Bootstrap

1. Initialize local git history.
2. Create or connect the GitHub repository.
3. Push the initial `main` branch.
4. After bootstrap, do all further work on dedicated branches with PRs, CI, and review.
