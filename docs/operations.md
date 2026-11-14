# Operations

Runtime configuration, container image, logging and metrics.

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
| `HTTP_WRITE_TIMEOUT` | `30s` | Response write deadline; also the request deadline (from arrival) that cancels pending detector calls |
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
(see [ADR 0012](adr/0012-container-image.md)).

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
  configure the probe in the orchestrator (Kubernetes `httpGet`, load balancer check, or an HTTP
  probe from a sidecar or auxiliary container).
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

## Prometheus metrics

`GET /metrics` on the API listener (prefixed by `API_PREFIX`, if configured)
exports Prometheus text metrics using `client_golang`. No extra port or environment
variable is required. When API keys are configured, scrapes require the same
`Authorization: Bearer ...` or `X-API-Key` header as scans. Only health is exempt
from authentication and admission. Scrapes consume admission capacity and retain
body limits and HTTP timeouts, so they can return 401, 413 or 503 under the same
conditions as other requests. Configure the scraper's credentials accordingly.

| Metric | Meaning |
| --- | --- |
| `guardrail_executions_total` | Completed policy evaluations and actual detector invocations |
| `guardrail_execution_duration_seconds` | Duration histogram for those same executions, in seconds (default Prometheus buckets) |
| `guardrail_systemone_routes_total{route}` | Cascade evaluations by deciding route: `judged`, `below_zone`, `above_zone`, `primary_failure`, `empty` |
| `guardrail_systemone_judgments_total{outcome}` | System One judgments per text: `success` or a failure kind (`masking_failed` and `text_too_large` send nothing) |
| `guardrail_systemone_judgment_duration_seconds{outcome}` | Judgment duration histogram, masking included |
| `guardrail_systemone_input_tokens_total` | Billable input tokens reported by successful responses |

The two execution metrics use labels `policy`, `mode`, `stage`, `detector`,
`action`, `decision` and `outcome`; the System One metrics use only the fixed
enumerations shown. `detector="none"` identifies a complete policy evaluation; its
`action="none"` and `decision` is the applied `NONE`, `BLOCKED` or
`GUARDRAIL_INTERVENED` (`none` on error). Detector series have `decision="none"`,
configured action `mask`, `block` or `annotate`, and count once per text and chain
step. `max_length` counts once per evaluation with action `block`; when it blocks,
no chain detectors run. Outcomes are `clean`, `match` and `error`. A matching
annotate/detect execution still reports a policy decision of `NONE`. These are
execution counts, not numbers of findings or HTTP requests. Earlier successful
steps remain counted if a later step fails. Cancellation and invalid spans are
errors when returned by the executed detector. Policy latency includes limits,
detectors and output processing; detector latency includes span validation.

Each handler owns a fresh registry. Embedders can inject a caller-owned registry
with `app.NewHandlerWithRegistry`; duplicate registrations return an error. No
Prometheus global registry, process/Go collectors or scrape metrics are installed.
Counters start when an execution completes, so unused series are absent. Health,
scrapes, authentication/admission rejections, validation failures and unknown
policies create no execution samples. This also prevents recursive scrape metrics.

Policy and detector labels are bounded by the startup catalog and fixed scan
policies; other labels are enums. Unexpected observer values collapse to
`unknown`. No request text, matches, extracted rules/types, keys, request IDs,
raw URLs or unknown user-selected policy names become labels. Cardinality grows
only with operator-loaded policies and detector chains. See
[ADR 0014](adr/0014-prometheus-observation.md).
