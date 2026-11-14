# ADR 0021: Optional System One gray-zone judge (Jev)

Status: Accepted

## Context

L10/L11 deliver a local prompt-injection classifier sidecar (Llama Prompt Guard 2
86M) behind `semantic_prompt_injection`. Its French false-positive rate at a
single threshold (16.1 % at 0.9, ADR 0020) keeps it in `annotate`. A second,
slower but calibrated opinion on the uncertain cases only could reduce false
positives without paying for every request.

TypeSafe's System One API (`POST /v1/systemone`, model Jev) answers typed
questions about a `state` with probabilities rather than free text. It is an
external, paid, network service: every byte sent leaves the deployment.

Primary references (read 14/11/2026, OpenAPI `info.version` 0.2.0):

- API reference: <https://docs.typesafe.ai/api/system-one.md> and
  <https://api.typesafe.ai/openapi.json> (only `/v1/models` and `/v1/systemone`
  exist; no credit or balance endpoint).
- Request rules and errors: <https://docs.typesafe.ai/api/errors.md> (32 MiB body,
  finite numbers only, 400/401/413/415/422/429/529).
- Models: <https://docs.typesafe.ai/models.md> (`jev-1.14.0`, `jev-1.13.0`;
  aliases `jev-latest`, `jev-preview` move between releases; 64k tokens per request,
  32k per question; per-organization rate limits).
- Primitives: <https://docs.typesafe.ai/primitives/noul.md>,
  <https://docs.typesafe.ai/primitives/choice.md>,
  <https://docs.typesafe.ai/primitives/score.md>; state:
  <https://docs.typesafe.ai/concepts/state.md>.
- Pricing: <https://help.typesafe.ai/articles/5187202169-how-much-does-jev-cost>
  (USD 0.042 per million input tokens, output free, prepaid credits, HTTP 402 when
  the balance is exhausted, 100k tokens/s and 80 requests/s per organization by
  default).

## Decision

### Client and contract

A new package `internal/semantic/systemone` holds a typed client for the documented
JSON contract and implements the existing `semantic.PromptInjectionDetector`
interface twice: a `Judge` (Jev alone) and a `Cascade` (primary classifier, then
the judge only inside a gray zone). The domain and policy engine are unchanged.

- Questions are typed (`noul`, `choice`, `score`); no free generation exists in
  the API or in this client. One fixed question named `prompt_injection` is asked
  per text. Its `instructions` and `criteria` are compile-time constants: operators
  choose the question type, never its wording, and no request field reaches them.
- The scanned text is data only: `state` is `{"untrusted_text": "<masked text>"}`.
  Instructions refer to the field by name and tell the model to treat it as data.
- Answer validation is strict: exactly the asked question name, matching `type`,
  finite probabilities in [0, 1], choice/score key sets equal to the asked
  options/levels, choice equal to an arg-max option, distributions summing to
  1 ± 0.05, score in [0, levels-1], confidence in [0, 1], non-negative usage and a
  non-empty `model`. Unknown fields are tolerated, trailing data is not. Response
  bodies are bounded (64 KiB). Any violation is a typed failure, never a score.
- The injection probability is: Noul `noul`; Choice probability of option
  `injection`; Score probability of the highest level (an explicit override
  attempt). It triggers when `>= SYSTEMONE_THRESHOLD` (default 0.7, the starting
  point suggested by the Noul page; not tuned on any corpus).
- Base URL and model are configuration with no default. The client posts to
  `<SYSTEMONE_BASE_URL>/v1/systemone`, so a gateway with a path prefix (for example
  a Cloudflare AI Gateway custom provider) works without code change. HTTPS is
  required except for loopback hosts. No user info, query or fragment. Redirects
  are never followed and environment proxies are not used, so the key is sent only
  to the configured host. The key comes from `SYSTEMONE_API_KEY_FILE` (preferred) or
  `SYSTEMONE_API_KEY`, exactly one of them, held in a redacting type.
- No retry: the guardrail is latency-bound and 429/529/402 are reported as typed,
  bounded failure kinds. Caller cancellation always wins.

### Mandatory masking before any network call

The judge requires a `Masker`. The app builds an internal policy (not in the user
catalog, not observable through it) with `detect_secret` and `detect_pii` in
`mask` with `[{TYPE}]`, evaluated by a dedicated engine on the original text. It
contains the embedded default detectors and, when `GUARDRAILS_CONFIG_DIR`
overrides their patterns, the operator detectors too, so an override can add but
never remove masking coverage. A judge-only Unicode email rule is added because
the user-facing `detect_pii` email rule is ASCII-only and would leave the
non-ASCII part of a local part (`jérô` in `jérôme.dupont@...`) in clear;
`detect_pii` itself is unchanged. The internal policy never contains a semantic
detector, so the judge cannot recurse. If masking fails (detector error, invalid
UTF-8, cancellation) or the masked text exceeds `SYSTEMONE_MAX_TEXT_RUNES`, no
HTTP request is made and the detection fails in either failure mode. These
failures are provoked by the input (for example a literal U+FFFD rejected by the
detectors), so `SYSTEMONE_FAILURE_MODE=open` applies only to provider failures:
otherwise a caller could turn the judge off with crafted text and, in cascade,
replace a primary result inside the zone with a degraded pass. Findings are still reported on the
original text (whole-text span), so original positions are preserved.

### Cascade and modes

`SYSTEMONE_MODE=cascade` (default) requires `SEMANTIC_ENABLED=true`. The primary
classifier scores every text. If its maximum score `s` satisfies
`SYSTEMONE_ZONE_LOWER <= s <= SYSTEMONE_ZONE_UPPER` (closed interval, both bounds
inclusive, required, in [0, 1], `lower <= upper`), the judge decides. Outside the
zone the primary decision stands and no judge call is made. A primary failure is
never turned into a score of 0: a degraded or failed primary assessment is passed
through unchanged and the judge is not called.

`SYSTEMONE_MODE=judge_only` requires `SEMANTIC_ENABLED=false` and asks the judge for
every non-blank text, still masked. It exists for the evaluation bench.

Both modes keep the detector name `semantic_prompt_injection`, so policies and the
bench switch backends by environment only. A judge decision reports rule
`systemone_judge`; a primary decision keeps `semantic_classification`.

### Observability

Metrics on the handler's private registry, labels from fixed enumerations only:
`guardrail_systemone_routes_total{mode,route}`,
`guardrail_systemone_judgments_total{outcome}`,
`guardrail_systemone_judgment_duration_seconds{outcome}` and
`guardrail_systemone_input_tokens_total`. Policy/detector/action metrics of the
engine are unchanged. Errors and logs carry the failure kind and, for status
failures, the code only: never text, headers, keys, URLs or response bodies.

## Alternatives considered

- Judge every request: simplest, but pays network latency and cost on every text
  and sends all traffic out; kept only as `judge_only` for measurement.
- Let operators write the question: flexible, but turns configuration into prompt
  injection surface and breaks comparability of measurements.
- Retry 429/529 with backoff as the SDKs do: improves availability but makes
  guardrail latency unbounded within the request deadline; left to a follow-up.
- Send the raw text and rely on the provider's data handling: rejected; masking is
  a hard precondition.
- Treat a primary failure as score 0 (below the zone): silently skips both
  detectors; rejected.

## Consequences

- Positives: an external calibrated second opinion limited to the uncertain band;
  disabled by default; no change to the offline default service, domain contracts,
  scan routes or LiteLLM contract.
- Negatives: one more external dependency, a paid one, with its own latency
  (per text, sequential, after the primary call; `HTTP_WRITE_TIMEOUT` is the
  request deadline that cancels pending calls) and rate
  limits. No credit balance endpoint exists, so a 402 is only seen at call time.
- Risks: masking covers what the secret and PII detectors cover (native secret
  rules and entropy, email (ASCII and Unicode), French phone numbers, IBAN, IPv4, payment cards, NIR,
  SIREN, SIRET); names, postal addresses, non-French phone formats and free-form
  identifiers are not masked. It reduces exposure; it is not a guarantee that no
  personal data leaves. Masking can also hide an injection carried inside a masked
  span. Zone bounds and threshold are uncalibrated until the bench measures them;
  pin a versioned model ID rather than an alias when thresholds are tuned.
