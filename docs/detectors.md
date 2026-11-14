# Detectors

Deterministic detectors (normalization, PII, prompt injection, native secrets) the optional semantic detector with its sidecar, and the optional System One judge.

## Normalized deterministic detection

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
([ADR 0007](adr/0007-policy-engine-and-findings.md)). Literal U+FFFD is
deliberately rejected too: after decoding,
it cannot be distinguished from damaged input. Offsets always refer to valid
original UTF-8, never to a repaired string. Policies that do not run a normalized
detector retain their existing behavior. No admission/body/rune limit changes.
See [ADR 0013](adr/0013-normalized-detector-integration.md).

## Native secret detection

Without a `detect_secret_contextual_patterns.yaml` override, `detect_secret`
uses the native [secret scanner](../internal/secrets/README.md): 217 embedded,
pinned MIT gitleaks rules, keyword assignments and Shannon entropy (base64
4.5, hex 3.0). Generic length/base64/hex regexes are retired. Bare git SHAs,
UUIDs, likely identifiers, templates and sequences are filtered; strong secret
assignment context still masks a hash-shaped password. No network verification,
Python process or scanner library is required. See [NOTICE](../NOTICE).

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
provider regexes scan the text. See [ADR 0017](adr/0017-secret-detector-integration.md).

For compatibility with the fixed evaluation contract, the adapter also retains
`compat:aws_access_key_id` (`AKIA` followed by 16 uppercase letters/digits,
word boundaries), including documentation examples excluded by upstream
allowlists. This conservative rule may mask public AWS examples; other native
allowlists remain unchanged. Legacy overrides retain their historical types
and masks, which differ from the native defaults above.

## Optional semantic detector

`semantic_prompt_injection` supports input and output policy stages. It is disabled
by default; embedded policies and legacy `/scan` behavior are unchanged. Enable
it explicitly and install [example policies](../examples/semantic/policies/policies.yaml)
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
| `SEMANTIC_MALICIOUS_LABELS` | `MALICIOUS` | Nonempty comma-separated TEI labels, case-insensitive (only `tei_predict`; Prompt Guard 2 checkpoints name their classes `LABEL_0`/`LABEL_1`, so use `LABEL_1`) |

These settings are operator-only. Request metadata, forwarded headers and provider
params never select URLs, credentials or thresholds. No sidecar auth forwarding
is implemented. Config parsing/handler construction makes no network calls.

For `scores`, POST `{"texts":["sample"]}` to the configured URL and return
`{"scores":[0.92]}` (one finite attack probability per item in original order).
For `tei_predict`, configure the full `/predict` URL; requests use
`{"inputs":[["sample"]],"raw_scores":false,"truncate":false}` and responses use
`[[{"label":"BENIGN","score":0.08},{"label":"MALICIOUS","score":0.92}]]`.
Use labels from the actual checkpoint's id2label mapping, not guessed label IDs.
The [L6a client contract](../internal/semantic/httpclassifier/README.md) documents
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

[Compose example](../examples/semantic/compose.yaml) wires the service to an external
sidecar on `classifier:8080/classify`. Set `SEMANTIC_SIDECAR_IMAGE` to your compatible
image (prefer an immutable digest). The example deliberately supplies no model
image and is not a verified model deployment. Build/Compose validation belongs on
the designated build host; it was not run on docker-box for this change.

Prompt Guard 2 offers 22M/86M checkpoints; Meta describes its mDeBERTa basis and
Llama 4 license in the [primary implementation documentation](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/README.md).
Check the [22M model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M)
and [86M model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
for access, label mapping, license and use restrictions before downloading.
The FP32 weights are 283 MB (22M) and 1.1 GB (86M, large multilingual vocabulary);
runtime memory and tokenization add overhead. Checkpoints are not bundled. The [TEI supported architectures](https://huggingface.co/docs/text-embeddings-inference/supported_models)
do not list mDeBERTa: a TEI `/predict` wire format does **not** establish Prompt Guard
compatibility with a stock TEI image. Supply a compatible external server or a
validated custom implementation; no Python runtime, CGO, model or provider is
required by the Go service or its fixed-fixture/httptest suites. The rune chunk
heuristic does not guarantee a checkpoint token limit; calibrate the sidecar and
threshold against your traffic before deployment. See [ADR 0016](adr/0016-semantic-policy-adapter.md).

## Semantic sidecar with a real model

[`deploy/semantic-sidecar`](../deploy/semantic-sidecar/README.md) is a deployable
CPU sidecar for the `scores` format: a small bounded Python service (no
`trust_remote_code`, safetensors only, non-root, read-only filesystem, offline at
runtime) that serves a prompt-injection classifier on `POST /classify`, with
`/healthz` and `/readyz`. The default model is
[`meta-llama/Llama-Prompt-Guard-2-86M`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
(multilingual, pinned commit, weights verified by sha256, labels `LABEL_0`/`LABEL_1`
with `LABEL_1` malicious and a load-time canary guarding the mapping). It is gated
and published under the Llama 4 Community License: the build needs your own Hugging
Face access, passed as a BuildKit secret (`HF_TOKEN`), and this repository ships no
weights and no image. **Built with Llama.** Llama 4 is licensed under the Llama 4
Community License, Copyright © Meta Platforms, Inc. All Rights Reserved; read the
"Llama license and distribution" section of the sidecar README before sharing an
image. The 22M model is a configuration profile; the previous default
[`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2)
(Apache-2.0, English only) stays available as a fallback profile. Model, revision and
attack labels are configuration; see
[ADR 0019](adr/0019-real-semantic-sidecar.md) (server, TEI decision: stock TEI
lists only CamemBERT and XLM-RoBERTa for sequence classification) and
[ADR 0020](adr/0020-llama-prompt-guard-2.md) (model choice, labels, licence).

```sh
# build host only; HF_TOKEN comes from your secret store through command substitution,
# never typed on a command line and never from a file in the repo
HF_TOKEN="$(<secret-store read command>)" docker compose -f deploy/semantic-sidecar/compose.yaml up --build
# no token: the public fallback
docker compose -f deploy/semantic-sidecar/compose.yaml \
  --env-file deploy/semantic-sidecar/profiles/deberta-fallback.env up --build
```

**Status.** Validated with the real models on the build host (`codex-dev`,
13/11/2026, head `eac5f59`): image build with a BuildKit secret, offline load of the
86M, 22M and DeBERTa checkpoints, the label mapping and canary, the `scores` contract,
the Compose stack (readiness, isolated network, hardening, bounded drain on SIGTERM)
and the Go service against the sidecar. The drain covers only the current sidecar HTTP
request: an analysis spanning multiple chunk batches can have its next batch refused
during shutdown. The Go service then applies its configured failure mode (sanitized
502 when fail-closed, degraded pass-through when fail-open).

**Quality (measured, threshold `0.9`, same protocol for each model).** On the 62-case
French injection corpus the deterministic detector scores 29 TP / 1 FP / 30 TN / 2 FN
(recall 93.5%, FPR 3.2%). The 86M model alone scores 11 / 4 / 27 / 20 (35.5% / 12.9%)
and the two combined 30 / 5 / 26 / 1 (96.8% / 16.1%). The previous DeBERTa default
alone scored 30 / 27 / 4 / 1 (96.8% / 87.1%). On the original corpus (83 cases, French
and English reported apart in the evaluation) the 86M model alone finds 8 of 13
attacks with no false positive, and combined with the deterministic detector the
result is identical to the deterministic detector (13 TP, 1 FP); DeBERTa flagged 36 of
70 negatives. The 86M model is therefore a low-noise second opinion, not a French
blocking detector: its false-positive rate on French injection negatives (16.1%) is
above the 5% bar set beforehand for `block`, so the examples stay in **`annotate`**.
Full tables, provenance (commit, threshold, hardware, n, repetitions) and limits:
[`deploy/semantic-sidecar/EVALUATION.md`](../deploy/semantic-sidecar/EVALUATION.md).
Latency adds about 165-170 ms p50 / 200-210 ms p95 on 2 shared vCPUs (the
deterministic detector takes about 0.3 ms).

**Recommendation.** Keep the semantic detector disabled by default. If you enable
it, use `semantic_prompt_injection: annotate` with `prompt_injection: block`, as
the [example `semantic` policy](../examples/semantic/policies/policies.yaml) does.
A policy that explicitly sets the semantic detector to `block` (example
`semantic-block`) remains configurable, but a semantic block takes precedence over a
secret `mask` in the same policy: a text the model calls an injection (typically
`password=…`) is refused whole instead of being redacted, regardless of the order of the
detector steps within the same evaluated stage (input and output are evaluated
separately), in enforce mode. With the previous DeBERTa model
this happened often; the 86M model rarely flags credential texts in the corpora, but the
precedence rule is unchanged. It is a limit of the models, not an API defect.
The real-model check is a Go test behind the `realsidecar` build tag (excluded
from `go test ./...` and from GitHub CI):

```sh
SEMANTIC_SIDECAR_URL=http://127.0.0.1:18080 SEMANTIC_SIDECAR_FRENCH=1 \
  go test -tags realsidecar ./tests/integration/semantic_sidecar -run TestRealModel -count=1 -v
```

**Size `SEMANTIC_TIMEOUT` for your text limit.** On the test host (2 shared vCPUs,
inference serialized) a 510-character chunk costs about 200 ms with the 86M model (L11, French text; the
older 125 ms figure came from another image and load and is not comparable). 32
chunks took 6.5 s, so the `2s` Go default fails on texts of about 10 chunks or more.
`MAX_TEXT_CHARS=20000` is about 45 chunks (510 characters with a 64-character overlap), roughly 9 s at low
load (extrapolated, not measured at that size): the Compose default of `10s` leaves
almost no margin, so use 15 s or more for `SEMANTIC_TIMEOUT`, or lower `MAX_TEXT_CHARS`; recalibrate under concurrency
(`HTTP_MAX_CONCURRENT_REQUESTS`) and keep `HTTP_WRITE_TIMEOUT` and any upstream
guardrail timeout above the worst whole request. `SEMANTIC_FAILURE_MODE=closed`
returns 502 when the sidecar fails, times out or rejects an over-long text; `open`
passes the text and logs `semantic classifier degraded`. `SEMANTIC_THRESHOLD` is
per-model and must be calibrated on your data (the sidecar returns probabilities
only). The 510-rune chunking stays a heuristic: the sidecar counts real tokens and
answers 422 rather than truncating. The sidecar deadline is cooperative (observed
between micro-batches, so one micro-batch can overrun it) and a request the client
abandoned can keep a serialized sidecar busy. Measurements, formulas and caveats:
[sidecar README](../deploy/semantic-sidecar/README.md#measured-results-and-limits).
The Compose stack attaches the sidecar only to an `internal: true` network.

## Optional System One judge

`semantic_prompt_injection` can ask TypeSafe's
[System One API](https://docs.typesafe.ai/api/system-one.md) (model Jev) for a
second opinion. It is disabled by default and contacts no network when disabled.
The client asks one typed question (`noul`, `choice` or `score`) with fixed,
compiled-in wording; the scanned text is sent only as data in
`state.untrusted_text`. Answers are validated strictly (question name and type,
finite probabilities in [0, 1], option and level sets, sums within 0.05 of 1,
bounded 64 KiB body); anything else is a typed failure, never a score. Design and
primary references: [ADR 0021](adr/0021-systemone-gray-zone-judge.md) and the
[package README](../internal/semantic/systemone/README.md).

**Modes.** `cascade` (requires `SEMANTIC_ENABLED=true`) scores every text with the
sidecar and asks the judge only when the sidecar score `s` satisfies
`SYSTEMONE_ZONE_LOWER <= s <= SYSTEMONE_ZONE_UPPER` (both bounds inclusive).
Outside the zone the sidecar decides and no judge request is made. A sidecar
failure is never read as a score of 0: the judge is not called and
`SEMANTIC_FAILURE_MODE` applies. `judge_only` (requires `SEMANTIC_ENABLED=false`)
judges every non-blank text, for measurement. Both keep the detector name, so
policies do not change; a judge decision reports rule `systemone_judge`.

**Masking is mandatory.** Before any request, each text is masked by an internal
policy (not part of the catalog, never containing a semantic detector) with
`detect_secret` and `detect_pii` and typed masks such as `[EMAIL]`, plus a
judge-only Unicode email rule (quoted local parts and IP-literal domains are not
covered). It always includes the embedded default rules and,
with `GUARDRAILS_CONFIG_DIR`, the operator rules too: overrides add coverage, never
remove it. If masking fails or the masked text exceeds `SYSTEMONE_MAX_TEXT_RUNES`,
nothing is sent and the request fails (502) in either failure mode: these failures
come from the input, and `open` must not let crafted text switch the judge off. Findings keep original positions (whole
original text) and client texts are never rewritten by the judge. **Coverage is
bounded:** native secret rules and entropy, email, French phone numbers, IBAN,
IPv4, payment cards, NIR, SIREN and SIRET. Names, postal addresses, other phone
formats, free-form identifiers and secrets written in prose (a password stated in a
sentence, not as an assignment) are not masked; this reduces exposure, it does
not guarantee that no personal data leaves. Validated formats are masked only when
they validate: the bench (ADR 0023) found that the all-zero demonstration card number
of one synthetic case (`0000 0000 0000 0000`) is not masked by the `payment_card`
validator, so its bench egress guard refused that request.

| Variable | Default | Notes |
| --- | --- | --- |
| `SYSTEMONE_ENABLED` | `false` | Boolean |
| `SYSTEMONE_MODE` | `cascade` | `cascade` or `judge_only` |
| `SYSTEMONE_BASE_URL` | empty | Required when enabled. `https` (http only for loopback), no credentials, query or fragment; requests go to `<base>/v1/systemone`, so a gateway path prefix works |
| `SYSTEMONE_MODEL` | empty | Required when enabled, for example `jev-1.14.0`; pin a versioned ID once thresholds are tuned (aliases move) |
| `SYSTEMONE_API_KEY_FILE` | empty | File holding the key (preferred); exactly one of the two key variables is required when enabled |
| `SYSTEMONE_API_KEY` | empty | Key value; never logged or echoed |
| `SYSTEMONE_QUESTION` | `noul` | `noul`, `choice` (probability of option `injection`) or `score` (probability of the top level) |
| `SYSTEMONE_THRESHOLD` | `0.7` | Probability in (0, 1]; equality triggers. Starting point from the Noul docs, not calibrated |
| `SYSTEMONE_ZONE_LOWER` / `SYSTEMONE_ZONE_UPPER` | empty | Required in `cascade`; in [0, 1], lower <= upper, inclusive |
| `SYSTEMONE_TIMEOUT` | `3s` | Per text; texts are judged one after another and in cascade each also waits for `SEMANTIC_TIMEOUT`. `HTTP_WRITE_TIMEOUT` bounds the whole request and cancels pending calls |
| `SYSTEMONE_FAILURE_MODE` | `closed` | Provider failures only. `closed`: 502; `open`: the text passes and `semantic classifier degraded` is logged. Input-provoked failures (masking, size, provider 400/413/422 `rejected_input`) and cancellation always fail |
| `SYSTEMONE_MAX_TEXT_RUNES` | `20000` | Larger masked texts fail without being sent |

The key is sent only as `Authorization: Bearer` to the configured host: no
redirect is followed, environment proxies are ignored, and caller headers are
never forwarded. Errors and logs carry a failure kind (`unauthorized`,
`payment_required`, `rate_limited`, `overloaded`, `rejected_input`, `timeout`, `masking_failed`,
`invalid_probability`, ...) and at most a status code. There is no retry.

**Cost and limits** (primary sources, read 14/11/2026): USD 0.042 per million
input tokens, output free, prepaid credits; an exhausted balance returns 402
([pricing](https://help.typesafe.ai/articles/5187202169-how-much-does-jev-cost)).
Default rate limits are 100k tokens/s and 80 requests/s per organization; the
context is 64k tokens per request ([models](https://docs.typesafe.ai/models.md)).
The public API has no balance endpoint (`/v1/models` and `/v1/systemone` only), so
watch `guardrail_systemone_input_tokens_total` and 402 outcomes.
