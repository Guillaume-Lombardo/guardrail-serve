# guardrail-serve

Native Go service for serving LLM guardrails.

The public HTTP contract is exposed through `huma`, so the registered Go request/response types are the source of truth for the generated OpenAPI document and Swagger UI.

## Status

This repository is migrating from the archived Python reference implementation in `archive/bdf-guardrails` to a native Go implementation focused on lower latency, smaller images, and clearer operational boundaries.

`archive/` is reference material only and must never be committed as part of active delivery work.

## Current Target

The first Go implementation serves deterministic guardrails on:

- `/scan/secrets`
- `/scan/pii`
- `/scan/prompt-injection`
- `/v1/guardrails/{policy}`
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

### Supported scopes

The deterministic detectors `detect_secret`, `detect_pii` and
`prompt_injection`, and the `max_length` payload limits, support both
`request` and `response`. `input_type=request` evaluates a policy's `input`
stage and `input_type=response` its `output` stage, on every route. With the
`prompt_injection` policy, pre-call request texts and post-call response texts
return `BLOCKED` when injection patterns match, and `NONE` for clean texts.
Unknown scopes remain invalid (HTTP `422`).
The optional semantic prompt-injection library guardrail remains request-only
and is not registered by the HTTP server.

### Route contracts

All scan requests require at least one `texts` entry; `input_type` defaults to
`request` and accepts `request` or `response`. `request_data` accepts arbitrary
metadata, including LiteLLM `user_api_key_*` values, without evaluating it.

`/scan/*` uses a strict schema: unknown fields and non-empty `images`, `tools`,
`tool_calls`, and `structured_messages` are rejected. Responses retain
`decision`, `texts`, `metadata`, and optional `reason`.

`/scan/*` keep their historical behavior: each runs one fixed detector in
enforce mode (secrets and PII masked with `SECRET_MASK`, prompt injection
blocked) and policy files cannot change them.

### Policies

`POST /v1/guardrails/{policy}` evaluates a named policy. It uses the strict
native schema: `texts` (at least one), optional `input_type`
(`request` | `response`, default `request`) and opaque `request_data`; unknown
fields return `422`. Unknown policies return `404` with
`{"detail":"Unknown policy 'name'."}`.

For `{"texts":["write to zoe@ex.fr"]}` on `/v1/guardrails/default`:

```json
{
  "policy": "default", "mode": "enforce", "stage": "input",
  "decision": "GUARDRAIL_INTERVENED", "policy_decision": "GUARDRAIL_INTERVENED",
  "texts": ["write to [EMAIL]"],
  "findings": [{"text_index": 0, "detector": "detect_pii", "type": "EMAIL",
    "rule": "email", "start": 9, "end": 18, "action": "mask"}]
}
```

`start` (inclusive) and `end` (exclusive) are Unicode code point offsets into
the original text item `text_index`, even after masks change its length.
Findings never contain the matched value, are sorted by `text_index`, `start`,
`end`, chain position and rule, and `score` appears only for detectors that
provide one. `reason` is a value-free explanation when `policy_decision` is
`BLOCKED`.

Policies are loaded at startup from the embedded
`internal/resources/defaults/policies.yaml`, or from
`GUARDRAILS_CONFIG_DIR/policies.yaml`, which replaces the embedded catalog
entirely:

```yaml
version: 1
policies:
  - name: default
    mode: enforce          # enforce | detect
    stages:                # both stages required; [] applies only payload limits
      input:               # ordered chain; each detector at most once
        - detector: prompt_injection
          action: block    # block | mask | annotate
        - detector: detect_pii
          action: mask
          mask: "[{TYPE}]" # optional; default SECRET_MASK
      output: []
```

- `block` returns `BLOCKED` with the original texts; `mask` replaces spans and
  returns `GUARDRAIL_INTERVENED`; `annotate` only reports findings.
- `detect` mode never changes texts and always returns `decision: NONE`;
  `policy_decision`, `reason` and findings show what `enforce` would do.
- Every detector scans the original text. Overlapping masked spans merge into
  one replacement using the mask of the earliest chain step; touching spans
  merge only when they render the same mask.
- `{TYPE}` in a mask expands to the finding type, such as `EMAIL`,
  `PHONE_NUMBER`, `IBAN`, `IP_ADDRESS`, `CREDIT_CARD`, `PASSWORD`, `API_KEY`
  or `PROMPT_INJECTION`. Pattern files set it per rule with `type:`; rules
  without it use `SECRET`, `PII` or `PROMPT_INJECTION`. `detect_secret` and
  `detect_pii` rules must contain a `(?P<secret>...)` group.
- Payload limits run first in every mode and block oversized payloads.
- Unknown fields, modes, actions, stages or detectors, duplicates and
  incomplete definitions fail startup with the file and position.

Embedded policies: `detect_secret`, `detect_pii`, `prompt_injection`,
`max_length` (limits only), `default` (input: block injections, mask secrets,
typed PII masks; output: mask secrets and typed PII, annotate injections) and
`audit` (the same chains in detect mode). See
[ADR 0007](docs/adr/0007-policy-engine-and-findings.md).

### LiteLLM route

`/beta/litellm_basic_guardrail_api` implements the
[LiteLLM Generic Guardrail API](https://docs.litellm.ai/docs/adding_provider/generic_guardrail_api).
It accepts `litellm_call_id`, `litellm_trace_id`, `litellm_version`,
`request_headers`, and `additional_provider_specific_params`, and ignores unknown
fields. `additional_provider_specific_params.policy` selects the evaluated
policy; when that key is absent, `LITELLM_DEFAULT_POLICY` applies. A `policy`
value that is not a non-empty string, or names an unknown policy, returns
`400` instead of passing the request through. Other parameters, `request_data`
and forwarded headers are opaque: they do not select policies, authenticate
callers, or change guardrail settings. In the LiteLLM guardrail definition,
set the policy next to the other `litellm_params`:

```yaml
- guardrail_name: guardrail-serve
  litellm_params:
    guardrail: generic_guardrail_api
    api_base: http://guardrail-serve:8000
    additional_provider_specific_params:
      policy: default
```

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

The LiteLLM response does not expose `decision`, `metadata` or findings. A
policy in detect mode returns `NONE` with unchanged texts.

Requests reaching the API return an `X-Request-ID` header. Client IDs are reused only when they contain 1–128 ASCII letters, digits, dots, underscores or hyphens (`[A-Za-z0-9._-]`); otherwise an ID is generated. Logged User-Agent values are limited to 256 bytes of valid UTF-8. The server caps headers at 32 KiB (net/http adds a small parser allowance); larger headers receive HTTP `431`.

## Runtime configuration

`LITELLM_DEFAULT_POLICY` (default `detect_secret`) names the policy used by the
LiteLLM route when the request selects none. The legacy
`LITELLM_GUARDRAIL_NAME` is read when `LITELLM_DEFAULT_POLICY` is empty; its
historical values are embedded policy names. An undefined policy fails startup.
`GUARDRAILS_CONFIG_DIR` overrides `policies.yaml` and the pattern files.

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
| `HTTP_MAX_CONCURRENT_REQUESTS` | `2` | Maximum admitted requests, excluding health |
| `GUARDRAIL_API_KEYS` | empty | Optional comma-separated API keys |

Timeouts accept positive Go durations such as `500ms` or `30s`; invalid,
non-positive or overflowing settings fail startup. The body limit must be a
positive integer from `1` to `1048576`, inclusive. The transport middleware owns this ceiling. Oversized requests return HTTP `413`,
including bodies with unknown content length. Body read failures return `400`.
`HTTP_MAX_CONCURRENT_REQUESTS` must be a positive integer; invalid, non-positive
or overflowing values fail startup. Admission is nonblocking, after authentication
and before body reading or parsing. Saturation returns `503` with
`{"detail":"Service busy."}` and `Retry-After: 1`; missing credentials still
return `401`. Health bypasses admission and body buffering.
Malformed 1 MiB JSON can use roughly 120 MiB during schema validation in measured
cases. The default of 2 limits simultaneous expensive requests, not total process
memory: allow roughly 240 MiB for those cases plus baseline, GC and operational
headroom, and size this setting against the deployment memory budget. This is an
observed amplification, not a proven worst-case heap bound.
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

## Container

The repository ships a multi-stage `Dockerfile` that builds a small, static, non-root image
(see `docs/adr/0012-container-image.md`).

```bash
docker build -t guardrail-serve .
docker run --rm -p 127.0.0.1:8000:8000 guardrail-serve
curl http://127.0.0.1:8000/health/
```

- **Build**: Go toolchain image pinned by tag and digest (it must match the `go` directive of
  `go.mod`), `CGO_ENABLED=0`, `-trimpath -buildvcs=false -ldflags="-s -w"`. The default policies and
  patterns are embedded in the binary, so no resource file is copied separately.
- **Runtime**: `gcr.io/distroless/static-debian13:nonroot` (pinned by digest) with CA certificates,
  no shell and no package manager. The process runs as `65532:65532` from the read-only, root-owned
  `/app/guardrail-serve` and writes nothing to disk.
- **Port**: the service listens on `API_PORT` (default `8000`, `EXPOSE 8000`). Publish it on the
  interface you intend to serve; keep `GUARDRAIL_API_KEYS` set when it is reachable by others.
- **Configuration**: every setting described in [Runtime configuration](#runtime-configuration)
  is an environment variable (`docker run -e LOG_FORMAT=json -e GUARDRAIL_API_KEYS=...`).
  `GUARDRAILS_CONFIG_DIR` must point to a directory mounted into the container and readable by
  uid `65532` (for example `-v ./config:/config:ro -e GUARDRAILS_CONFIG_DIR=/config`). Pass secrets
  through the orchestrator's secret mechanism, never bake them into the image.
- **Health**: `GET <API_PREFIX>/health/` returns `200 {"status":"ok"}` and is exempt from API-key
  authentication. The image has no `HEALTHCHECK` instruction because it contains no shell or curl:
  configure the probe in the orchestrator (Compose `healthcheck` from another container, Kubernetes
  `httpGet`, load balancer check).
- **Signals**: the binary is PID 1 through an exec-form `ENTRYPOINT` and handles `SIGTERM` and
  `SIGINT` itself: it stops accepting connections and drains requests for up to
  `HTTP_SHUTDOWN_TIMEOUT` (default `10s`). Set the orchestrator's stop grace period above that value
  (`docker stop -t 15`).
- **CI**: `.github/workflows/container.yml` builds the image on pull requests without pushing it;
  it needs no registry credentials. Publishing is out of scope for now.

## Logging

Logging uses the Go stdlib `log/slog` stack.

- `LOG_FORMAT=human` emits readable text logs for local development and operator inspection
- `LOG_FORMAT=json` emits structured JSON logs for export pipelines and machine processing

Request logs include contextual fields such as request id, method, path, guardrail or policy, input type, decision, finding count, status code, and duration. Texts, findings and matched values are never logged.

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
- `internal/domain`: guardrail, detector, finding and policy enum contracts
- `internal/guardrails`: built-in detectors and payload limits
- `internal/policy`: policy schema, catalog and evaluation engine
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
