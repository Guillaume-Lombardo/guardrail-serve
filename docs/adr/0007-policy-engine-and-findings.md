# ADR 0007: Shared policy engine and findings

## Status

Accepted

## Context

Each guardrail used to own its detection, redaction and response shaping.
`detect_secret` and `detect_pii` duplicated the same regex/redaction loop, the
LiteLLM route could run exactly one configured guardrail, and no route reported
where a detection occurred. Operators need named, auditable policies that chain
detectors, choose an action per detector, differ between input and output, and
can run in shadow mode, without coupling that logic to HTTP or to providers.
Future French normalization (L4) must be able to scan a rewritten view of a
text while still reporting positions in the original text.

## Decision

### Layers

- `internal/domain` holds the contracts: `Stage`, `Action`, `Mode` (typed
  enums with explicit `Parse*` functions), `Detection`, `Detector` and
  `Finding`.
- `internal/guardrails` implements detectors. One shared `RegexDetector`
  replaces the duplicated secret/PII loops; each detector declares only its
  name, default finding type, span selection (`secret` capture groups or whole
  match) and a fixed block reason.
- `internal/policy` compiles and evaluates policies: `Parse` (YAML schema),
  `NewPolicy`, `Catalog`, `Engine`. It imports only the domain.
- `internal/resources` loads `policies.yaml`; `internal/app` wires detectors,
  catalog and engine; `internal/httpapi` maps transports onto evaluations.

### Policy schema (version 1)

```yaml
version: 1                      # required, only 1 is accepted
policies:                       # required, non-empty, evaluated by name
  - name: default               # required, ^[a-z0-9][a-z0-9_-]{0,63}$, unique
    description: optional text
    mode: enforce               # required: enforce | detect
    stages:                     # both keys required; [] = payload limits only
      input:                    # ordered chain, each detector at most once
        - detector: detect_pii  # detect_secret | detect_pii | prompt_injection
          action: mask          # required: block | mask | annotate
          mask: "[{TYPE}]"      # optional, only with action mask
      output: []
```

Decoding uses `KnownFields`: unknown fields anywhere are errors. Unknown modes,
actions, stages or detectors, missing or null stages, missing mode or action,
duplicate policy names, duplicate stage keys, duplicate detectors in a chain,
`mask` on a non-mask step, invalid mask templates, empty files, several YAML
documents and other versions are rejected at startup with the file and
position in the message. Nothing falls back to another policy.

The embedded catalog provides `detect_secret`, `detect_pii`,
`prompt_injection` and `max_length` (the values historically accepted by
`LITELLM_GUARDRAIL_NAME`), plus `default` and its shadow twin `audit`.
`GUARDRAILS_CONFIG_DIR/policies.yaml` replaces the embedded catalog entirely;
catalogs are never merged.

### Scopes and stages

Transports keep `input_type` (`request` | `response`). It maps to stage
`input` | `output`. Policies only speak in stages; detectors declare the
stages they support and a chain referencing an unsupported stage is rejected.

### Evaluation

1. Payload limits (`MAX_TEXT_ITEMS`, `MAX_TEXT_CHARS`) run first in every mode.
   Exceeding them returns `BLOCKED` with the limit reason and no findings.
   They protect resources and are not policy actions.
2. Every step of the stage chain runs on the original text of every item, in
   chain order. Steps never see earlier rewrites, so all spans address the same
   text. All steps run even when an earlier one blocks, so detect mode and
   audits see every finding.
3. `policy_decision` is `BLOCKED` if any finding has action `block`, else
   `GUARDRAIL_INTERVENED` if any has `mask`, else `NONE`. `annotate` only
   reports.
4. `enforce` applies it: blocked requests return the original texts, masked
   requests return rewritten texts. `detect` always returns `decision: NONE`
   and the original texts, while still returning `policy_decision`, `reason`
   and findings.
5. The block reason is the fixed reason of the earliest blocking chain step;
   reasons never contain text values.

### Findings

`{text_index, detector, type, rule, start, end, score?, action}`. `start` and
`end` are Unicode code point (rune) offsets in the original text item, start
inclusive and end exclusive. Detectors report byte offsets on rune boundaries;
the engine rejects empty, out-of-range or rune-splitting spans as detector
failures (HTTP 502), then projects them onto rune offsets. Findings are sorted
by `text_index`, `start`, `end`, chain position, `rule`, `type`; exact
duplicates (same step, rule, type, span) are reported once. Findings never
contain matched values, and logs record only `policy`, `decision` and
`finding_count`.

L4 readiness: offsets are always projected through the engine's offset map.
Normalization will add a scanned view plus its map back to original bytes
before that projection; the finding contract does not change.

### Masking and overlaps

A mask step uses its `mask` template, or the literal `SECRET_MASK` when none is
declared. `{TYPE}` expands to the finding type (`[{TYPE}]` renders
`[EMAIL]`); other braces are rejected; masks are at most 64 runes. `SECRET_MASK`
is never expanded. Rewriting happens once per text, on byte offsets of the
original text, so it cannot split UTF-8 sequences:

- overlapping masked spans merge into one replacement;
- touching spans merge only when they render the same mask (this preserves the
  historical single `[REDACTED]` for adjacent secrets);
- a merged span uses the mask of its highest-priority finding: earliest chain
  step, then earliest start, then longest span, then rule name.

Findings keep their own original offsets even when their span was merged or
the text length changed. Output texts are always aligned one to one with input
texts.

### Transports

- `POST /v1/guardrails/{policy}`: strict native contract (`texts`,
  `input_type`, opaque `request_data`; unknown fields 422). Unknown policies
  return 404; only syntactically valid names are echoed in the detail. The
  response contains `policy`, `mode`, `stage`, `decision`, `policy_decision`,
  `texts`, `findings` and optional `reason`.
- `/beta/litellm_basic_guardrail_api`: `additional_provider_specific_params.policy`
  selects the policy. When the key is absent, `LITELLM_DEFAULT_POLICY` applies
  (legacy alias `LITELLM_GUARDRAIL_NAME`, default `detect_secret`), validated
  at startup. A present key that is not a non-empty string, or names an
  unknown policy, returns 400. The response keeps exactly `action`,
  `blocked_reason` (only when `BLOCKED`) and `texts`. `request_data`,
  `request_headers` and other parameters stay opaque, never select a policy
  and never authenticate. Images, tools, tool calls and structured messages
  remain accepted and unevaluated.
- `/scan/*` run fixed in-code single-detector enforce policies (mask with
  `SECRET_MASK`, or block for prompt injection) that overrides cannot change.
  Their schemas, decisions, masks, `metadata.guardrail`, ordered
  `metadata.matched_rules` and reasons are unchanged; a golden corpus recorded
  from the previous implementation guards this.

Authentication, admission and body limits stay in the transport middleware
(ADR 0006) and apply to every route, including the policy route.

## Alternatives considered

- Chain detectors on the previous step's output: offsets would refer to
  intermediate texts and the order would change spans. Rejected.
- Merge override catalogs with the embedded one: hides which policies exist and
  makes removal impossible. Rejected for whole-file replacement.
- Fall back to the default policy for unknown LiteLLM selections: silently
  weakens protection when a caller misspells a policy. Rejected.
- Treat payload limits as a policy step: they could then be disabled or run in
  detect mode, removing a resource guard. Rejected.
- Expose findings in the LiteLLM response: not part of the upstream contract.
  Deferred until LiteLLM defines such a field.

## Consequences

- Positives: one deterministic detection mechanism; named, validated policies
  with per-stage chains and shadow mode; findings usable by audits and the
  future evaluation lot; LiteLLM callers choose a policy per guardrail
  configuration.
- Negatives: pattern files now require a `(?P<secret>...)` group for
  `detect_secret`/`detect_pii` rules (previously such rules matched nothing),
  and an invalid policy file or undefined LiteLLM default prevents startup.
- Risks: large texts with many matches produce large finding lists; they are
  bounded by the existing text and body limits.
