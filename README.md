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
- Every detector reports spans in the original text (native deterministic
  detectors match a normalized view). Overlapping masked spans merge into
  one replacement using the mask of the earliest chain step; touching spans
  merge only when they render the same mask.
- `{TYPE}` in a mask expands to the finding type, such as `EMAIL`,
  `PHONE_NUMBER`, `IBAN`, `IP_ADDRESS`, `CREDIT_CARD`, `PASSWORD`, `API_KEY`,
  `SECRET`, `HIGH_ENTROPY_STRING` or `PROMPT_INJECTION`. Pattern files set it per rule with `type:`; rules
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

### Normalized deterministic detection

Native secret detection, PII and prompt-injection rules scan an NFKC view with zero-width and bidi
formatting controls removed. English and French hostile instruction overrides,
system-prompt disclosure and hostile tool use are covered by deterministic
patterns; ordinary requests such as “list the tools I need to build a shed”
pass. These patterns are bounded heuristics, not a semantic safety guarantee.
Secret detection is unchanged.

Matches map back to the original bytes through `internal/textnorm`; API findings
use original rune offsets. Masks replace whole original grapheme clusters.
Ligature expansions can produce overlapping findings, merged deterministically
by the policy engine. Clean text, detect-mode text and annotated text retain
all original characters, including formatting and decomposed accents.

PII rules accept an optional `validator` field: `payment_card`, `iban`, `fr_nir`,
`fr_siren`, or `fr_siret`; unknown validators fail startup. Embedded card rules
require Luhn (12–19 digits), IBAN rules require registered country format and
MOD 97, and French identifiers use the shared NIR/SIREN/SIRET validators.
NIR/SIREN/SIRET require their contextual labels (NIR also accepts “sécurité
sociale” and “numéro de sécurité sociale”) to avoid treating arbitrary numeric
sequences as identifiers. A labeled French identifier is not also treated as a
payment card. ASCII spaces/hyphens may separate identifier characters; NFKC
also accepts compatibility spaces and digits. Invalid checksums are discarded.
IPv4 literals remain detectable, except immediately after `version`, `release`,
`ver`, or `v` with optional spacing and `:`, `=`, `-` separators. Card matches
end at the last digit and preserve following spaces.

Native secret, PII and injection library detectors reject invalid UTF-8 and U+FFFD with a value-free
error, before returning any detections. JSON decoding replaces malformed UTF-8
and unpaired UTF-16 surrogates with U+FFFD; these decoded texts therefore also
fail closed through the existing detector-error HTTP 502 response, with the stable
JSON detail
`Guardrail execution failed.` and no texts, findings or input values
([ADR 0007](docs/adr/0007-policy-engine-and-findings.md)). Literal U+FFFD is
deliberately rejected too: after decoding,
it cannot be distinguished from damaged input. Offsets always refer to valid
original UTF-8, never to a repaired string. Policies that do not run a normalized
detector retain their existing behavior. No admission/body/rune limit changes.
See [ADR 0013](docs/adr/0013-normalized-detector-integration.md).
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

Both use labels `policy`, `mode`, `stage`, `detector`, `action`, `decision` and
`outcome`. `detector="none"` identifies a complete policy evaluation; its
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
[ADR 0014](docs/adr/0014-prometheus-observation.md).

## Evaluation

Run the versioned FR/EN offline regression gate from the repository root:

```sh
scripts/eval-offline.sh
```

Provision the Go toolchain specified in `go.mod` and modules first (`go mod download`).
Evaluation itself disables Go downloads, uses the real service over an ephemeral
loopback HTTP listener, and requires no datasets, models, LLM, API key or `.env`.
A request failure or regression produces a nonzero test/process exit status.

The gate measures two versioned corpora, always separately (never pooled), and
the separate Evaluation workflow uploads the artifacts from `.agent-tmp/eval/`:

| Corpus | Baseline | Artifacts |
|---|---|---|
| `guardrail-serve-original-v1` (83 cases) | [`original-v1.json`](tests/eval/baseline/original-v1.json) | `current.json`, `gate.json` |
| `guardrail-serve-french-injection-v1` (62 cases: 31 positives, 31 negatives) | [`french-injection-v1.json`](tests/eval/baseline/french-injection-v1.json) | `french-injection-v1.current.json`, `french-injection-v1.gate.json` |

Each baseline pins the corpus hash and per-case detections; all known false
positives/negatives remain visible by case ID. Metrics below are rounded for
readability; gates use full precision.

Original corpus (83 cases), as measured by the current baseline (after
[ADR 0018](docs/adr/0018-french-injection-recall.md)):

| Detector | Language | TP | FP | TN | FN | Precision | Recall | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| detect_pii | en | 8 | 2 | 34 | 0 | .800000 | 1 | .055556 |
| detect_pii | fr | 5 | 2 | 31 | 0 | .714286 | 1 | .060606 |
| detect_secret | en | 8 | 1 | 34 | 1 | .888889 | .888889 | .028571 |
| detect_secret | fr | 7 | 0 | 31 | 1 | 1 | .875000 | 0 |
| prompt_injection | en | 7 | 1 | 36 | 0 | .875000 | 1 | .027027 |
| prompt_injection | fr | 6 | 0 | 33 | 0 | 1 | 1 | 0 |

The six historical French injection cases are all detected (6/6) with no false
positive.

French prompt-injection corpus (62 cases, 31 positives and 31 negatives),
`prompt_injection`/`fr`:

| TP | FP | TN | FN | Recall | FPR |
|---:|---:|---:|---:|---:|---:|
| 29 | 1 | 30 | 2 | 93.5% | 3.2% |

The two false negatives (`frinj-pos-030`, `frinj-pos-031`) and the false
positive (`frinj-neg-011`) are kept as labelled known failures; see
[`tests/eval/README.md`](tests/eval/README.md) for the corpus, the families and
the failure analysis. On both corpora the gate also enforces absolute French
floors for `prompt_injection`/`fr`: recall at least 85% and FPR at most 5%, both
defined (ADR 0018). These are deterministic-rule results only; they say nothing
about the optional semantic sidecar. Its separate measurements and limitations
are documented in [`deploy/semantic-sidecar/EVALUATION.md`](deploy/semantic-sidecar/EVALUATION.md).

For every detector total and detector/language group, precision/recall must be
at least baseline and FPR at most baseline. Every previously correct case label
must remain correct: an improvement cannot compensate for a regression elsewhere.
Zero-denominator metrics use `defined: false` (no numeric bound); a previously
defined metric must remain defined. Corpora are never pooled.

To refresh after an improvement, run the old gate first, then:

```sh
GOPROXY=off GOTOOLCHAIN=local go test ./tests/eval \
  -run '^TestOfflineRegressionGate$' -count=1 -update-eval-baseline
```

The refresh refuses regressions against the old baseline. Review and commit the
old/new metrics and corrected case IDs as evidence; do not relax thresholds or
edit corpus labels to get a pass. See [ADR 0015](docs/adr/0015-offline-regression-gate.md)
and the [evaluation CLI documentation](cmd/guardrail-eval/README.md). Baseline refresh,
floors and the corpus are described in [`tests/eval/README.md`](tests/eval/README.md) and
[ADR 0018](docs/adr/0018-french-injection-recall.md).

### Optional semantic policy detector (L6b)

`semantic_prompt_injection` supports input and output policy stages. It is disabled
by default; embedded policies and legacy `/scan` behavior are unchanged. Enable
it explicitly and install [example policies](examples/semantic/policies/policies.yaml)
via `GUARDRAILS_CONFIG_DIR`; set `LITELLM_DEFAULT_POLICY=semantic` if appropriate.
A policy naming this detector while disabled fails startup as an unknown detector.

| Environment | Default | Contract |
| --- | --- | --- |
| `SEMANTIC_ENABLED` | `false` | Boolean; register optional detector |
| `SEMANTIC_URL` | empty | Required when enabled; static absolute HTTP(S) endpoint, no credentials/fragment |
| `SEMANTIC_FORMAT` | `scores` | `scores` or `tei_predict` |
| `SEMANTIC_TIMEOUT` | `2s` | Positive duration for one text, including all chunk batches |
| `SEMANTIC_THRESHOLD` | `0.9` | Finite score in (0,1]; equality triggers |
| `SEMANTIC_FAILURE_MODE` | `closed` | `open` or `closed` |
| `SEMANTIC_MALICIOUS_LABELS` | `MALICIOUS` | Nonempty comma-separated TEI labels, case-insensitive |

These settings are operator-only. Request metadata, forwarded headers and provider
params never select URLs, credentials or thresholds. No sidecar auth forwarding
is implemented. Config parsing/handler construction makes no network calls.

For `scores`, POST `{"texts":["sample"]}` to the configured URL and return
`{"scores":[0.92]}` (one finite attack probability per item in original order).
For `tei_predict`, configure the full `/predict` URL; requests use
`{"inputs":[["sample"]],"raw_scores":false,"truncate":false}` and responses use
`[[{"label":"BENIGN","score":0.08},{"label":"MALICIOUS","score":0.92}]]`.
Use labels from the actual checkpoint's id2label mapping, not guessed label IDs.
The [L6a client contract](internal/semantic/httpclassifier/README.md) documents
chunk/batch/response bounds and invalid-response behavior. Classification emits
one finding per triggered original text, with its maximum score and whole-text
rune span, fixed type `PROMPT_INJECTION` and rule `semantic_classification`.
It cannot locate the malicious fragment. Enforce/block blocks; annotate reports
findings without intervention; detect mode reports hypothetical actions unchanged.

Fail-closed provider errors return **502** `{"detail":"Guardrail execution failed."}`
without URLs, text, response bodies or secrets. Configure LiteLLM's own fail-closed
handling to block on provider errors. Fail-open can return `NONE`; each degraded
text evaluation emits a structured warning `semantic classifier degraded` with
fixed `detector` and `failure_mode` fields. Alert on that warning. L8b detector
metrics still record clean/match/error; fail-open counts as clean and requires the
warning to distinguish unavailable classification. Caller cancellation is never
converted to a successful fail-open result. LiteLLM responses keep exactly the
existing `action`, optional `blocked_reason`, and `texts` contract; no metadata is
added. Native v1 findings include the score and correct `text_index`.

[Compose example](examples/semantic/compose.yaml) wires the service to an external
sidecar on `classifier:8080/classify`. Set `SEMANTIC_SIDECAR_IMAGE` to your compatible
image (prefer an immutable digest). The example deliberately supplies no model
image and is not a verified model deployment. Build/Compose validation belongs on
the designated build host; it was not run on docker-box for this change.

Prompt Guard 2 offers 22M/86M checkpoints; Meta describes its mDeBERTa basis and
Llama 4 license in the [primary implementation documentation](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/README.md).
Check the [22M model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M)
and [86M model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
for access, label mapping, license and use restrictions before downloading.
Nominal FP32 weights alone are roughly 88/344 MB; runtime memory and tokenization
add overhead. Checkpoints are not bundled. The [TEI supported architectures](https://huggingface.co/docs/text-embeddings-inference/supported_models)
do not list mDeBERTa: a TEI `/predict` wire format does **not** establish Prompt Guard
compatibility with a stock TEI image. Supply a compatible external server or a
validated custom implementation; no Python runtime, CGO, model or provider is
required by the Go service or its fixed-fixture/httptest suites. The rune chunk
heuristic does not guarantee a checkpoint token limit; calibrate the sidecar and
threshold against your traffic before deployment. See [ADR 0016](docs/adr/0016-semantic-policy-adapter.md).

### Semantic sidecar with a real model (L10)

[`deploy/semantic-sidecar`](deploy/semantic-sidecar/README.md) is a deployable
CPU sidecar for the `scores` format: a small bounded Python service (no
`trust_remote_code`, safetensors only, non-root, read-only filesystem, offline at
runtime) that serves a prompt-injection classifier on `POST /classify`, with
`/healthz` and `/readyz`. The default model is
[`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2)
(Apache-2.0, pinned commit, **English only**, no jailbreak detection). Llama
Prompt Guard 2 is a documented configuration, not a default: it is gated and
needs the operator's access token and license acceptance. Model, revision and
attack labels are configuration; see
[ADR 0019](docs/adr/0019-real-semantic-sidecar.md) for sources, licenses and
the TEI decision (stock TEI lists only CamemBERT and XLM-RoBERTa for sequence
classification).

```sh
docker compose -f deploy/semantic-sidecar/compose.yaml up --build   # build host only
```

**Status.** Validated with the real model on the build host (`codex-dev`, head
`857e02c`): image build, model load, labels (`SAFE`/`INJECTION`), the `scores`
contract, token limits, container hardening, and the Go service against the sidecar
(fail-closed 502, fail-open `semantic classifier degraded` warning). **Still
`integration_pending`:** the Compose stack (`compose up`, isolated network,
restart, SIGTERM) at the final head.

**French quality (measured, threshold `0.9`).** On the 62-case French injection
corpus the deterministic detector scores 29 TP / 1 FP / 30 TN / 2 FN (recall 93.5%,
FPR 3.2%); the default English model alone scores 30 TP / 27 FP / 4 TN / 1 FN
(96.8% / 87.1%), and the two combined 31 TP / 27 FP / 4 TN / 0 FN (100% / 87.1%).
On the French cases of the original corpus the deterministic detector is 6 TP /
0 FP / 33 TN (the six attacks all found) and the model adds no true positive but
24 false positives (72.7% FPR). As an English control the model flags 12 of 37
negatives, mostly texts with secrets or PII. It gains two true positives on French
for 26 more false positives, so it is **not suitable as a French blocking
detector**. Full table, provenance (commit, threshold, hardware, n, repetitions)
and limits: [`deploy/semantic-sidecar/EVALUATION.md`](deploy/semantic-sidecar/EVALUATION.md).
Latency adds about 170 ms p50 / 210-225 ms p95 on 2 shared vCPUs (the
deterministic detector takes about 0.3 ms).

**Recommendation.** Keep the semantic detector disabled by default. If you enable
it, use `semantic_prompt_injection: annotate` with `prompt_injection: block`, as
the [example `semantic` policy](examples/semantic/policies/policies.yaml) does.
A policy that explicitly sets the semantic detector to `block` (example
`semantic-block`) remains configurable, but a semantic block takes precedence over a
secret `mask` in the same policy: a text the model calls an injection (typically
`password=…`) is refused whole instead of being redacted, regardless of the order of the
detector steps within the same evaluated stage (input and output are evaluated
separately), in enforce mode. This is a limit of the English model on French and on credential
texts, not an API defect.
The real-model check is a Go test behind the `realsidecar` build tag (excluded
from `go test ./...` and from GitHub CI):

```sh
SEMANTIC_SIDECAR_URL=http://127.0.0.1:18080 \
  go test -tags realsidecar ./tests/integration/semantic_sidecar -run TestRealModel -count=1 -v
```

**Size `SEMANTIC_TIMEOUT` for your text limit.** On the test host (2 shared vCPUs,
inference serialized) a 510-character chunk costs about 125 ms. The `2s` Go default
fails at 12 000 characters; the previous `5s` Compose default fails at 19 000.
`MAX_TEXT_CHARS=20000` needs **at least 8-10 s at low load** (the Compose stack now
defaults to `10s`) or a lower `MAX_TEXT_CHARS`; recalibrate under concurrency
(`HTTP_MAX_CONCURRENT_REQUESTS`) and keep `HTTP_WRITE_TIMEOUT` and any upstream
guardrail timeout above the worst whole request. `SEMANTIC_FAILURE_MODE=closed`
returns 502 when the sidecar fails, times out or rejects an over-long text; `open`
passes the text and logs `semantic classifier degraded`. `SEMANTIC_THRESHOLD` is
per-model and must be calibrated on your data (the sidecar returns probabilities
only). The 510-rune chunking stays a heuristic: the sidecar counts real tokens and
answers 422 rather than truncating. The sidecar deadline is cooperative (observed
between micro-batches, so one micro-batch can overrun it) and a request the client
abandoned can keep a serialized sidecar busy. Measurements, formulas and caveats:
[sidecar README](deploy/semantic-sidecar/README.md#measured-results-and-limits).
The Compose stack attaches the sidecar only to an `internal: true` network.

### Native secret detection

Without a `detect_secret_contextual_patterns.yaml` override, `detect_secret`
uses the native [secret scanner](internal/secrets/README.md): 217 embedded,
pinned MIT gitleaks rules, keyword assignments and Shannon entropy (base64
4.5, hex 3.0). Generic length/base64/hex regexes are retired. Bare git SHAs,
UUIDs, likely identifiers, templates and sequences are filtered; strong secret
assignment context still masks a hash-shaped password. No network verification,
Python process or scanner library is required. See [NOTICE](NOTICE).

Native secrets use the same normalization as PII/injection: invisible controls
are stripped and NFKC is applied for detection, then spans are mapped to original
bytes and complete graphemes before the engine emits original rune offsets.
Masking preserves surrounding original text. Rule names now use `gitleaks:`,
`keyword:` and `entropy:` prefixes; types are `SECRET` or `HIGH_ENTROPY_STRING`
(the latter includes the entropy score). Typed masks follow these types.

An explicit YAML secrets override in `GUARDRAILS_CONFIG_DIR` **replaces the
native scanner entirely**, retaining legacy regex matching on original text,
named `secret` captures, rule names and types. An empty override disables secret
detection. A missing file enables native defaults even when other overrides
exist. Remove the secrets override to migrate; copied older defaults retain
older behavior until removed. No secrets YAML is shipped in the default-resource directory, so copying
that directory to customize other resources keeps native detection enabled.
No environment variables changed.

Detection is heuristic, not exhaustive: plain unquoted word passwords,
multi-line YAML values, encoded secrets and some prose labels can be missed;
normalization can broaden matches. Provider allowlists and entropy filters can
produce false negatives; entropy can produce false positives. Limits and the
representative synthetic corpus are documented in the package README. Bound
request sizes and execution deadlines remain essential because all active
provider regexes scan the text. See [ADR 0017](docs/adr/0017-secret-detector-integration.md).

For compatibility with the fixed evaluation contract, the adapter also retains
`compat:aws_access_key_id` (`AKIA` followed by 16 uppercase letters/digits,
word boundaries), including documentation examples excluded by upstream
allowlists. This conservative rule may mask public AWS examples; other native
allowlists remain unchanged. Legacy overrides retain their historical types
and masks, which differ from the native defaults above.
