# HTTP API reference

Routes, request/response contracts, policies and the LiteLLM integration. Start from the [README](../README.md) for installation.

The public HTTP contract is exposed through `huma`: the registered Go request/response types are the source of truth for the generated OpenAPI document and Swagger UI.

## Routes

The service exposes:

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

## Supported scopes

The deterministic detectors `detect_secret`, `detect_pii` and
`prompt_injection`, and the `max_length` payload limits, support both
`request` and `response`. `input_type=request` evaluates a policy's `input`
stage and `input_type=response` its `output` stage, on every route. With the
`prompt_injection` policy, pre-call request texts and post-call response texts
return `BLOCKED` when injection patterns match, and `NONE` for clean texts.
Unknown scopes remain invalid (HTTP `422`).
The optional semantic prompt-injection library guardrail remains request-only
and is not registered by the HTTP server.

## Route contracts

All scan requests require at least one `texts` entry; `input_type` defaults to
`request` and accepts `request` or `response`. `request_data` accepts arbitrary
metadata, including LiteLLM `user_api_key_*` values, without evaluating it.

`/scan/*` uses a strict schema: unknown fields and non-empty `images`, `tools`,
`tool_calls`, and `structured_messages` are rejected. Responses retain
`decision`, `texts`, `metadata`, and optional `reason`.

`/scan/*` keep their historical behavior: each runs one fixed detector in
enforce mode (secrets and PII masked with `SECRET_MASK`, prompt injection
blocked) and policy files cannot change them.

## Policies

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
[ADR 0007](adr/0007-policy-engine-and-findings.md).

## LiteLLM route

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

## Request IDs and headers

Requests reaching the API return an `X-Request-ID` header. Client IDs are reused only when they contain 1–128 ASCII letters, digits, dots, underscores or hyphens (`[A-Za-z0-9._-]`); otherwise an ID is generated. Logged User-Agent values are limited to 256 bytes of valid UTF-8. The server caps headers at 32 KiB (net/http adds a small parser allowance); larger headers receive HTTP `431`.
