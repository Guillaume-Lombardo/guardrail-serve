# httpclassifier

`semantic.PromptInjectionDetector` backed by an external HTTP sidecar that
serves a prompt-injection classifier (for example Llama Prompt Guard 2 22M or
86M behind Hugging Face Text Embeddings Inference). The package is
self-contained: it is not registered in the runtime, reads no environment
variable and is wired by the policy/app layer in a later change (ADR 0010).

No model, weight or tokenizer is embedded, there is no CGO, and the only
dependency is the Go standard library.

## Usage

```go
classifier, err := httpclassifier.New(httpclassifier.Config{
	URL:         "http://prompt-guard:8080/predict",
	Format:      httpclassifier.FormatTEIPredict,
	Threshold:   0.8,
	Timeout:     2 * time.Second,
	FailureMode: httpclassifier.FailClosed,
	ModelName:   "llama-prompt-guard-2-22m",
})
assessment, err := classifier.DetectPromptInjection(ctx, texts)
```

`New` validates the configuration and performs no network call. A `Classifier`
is safe for concurrent use.

## Configuration

| Field | Required | Default | Notes |
|---|---|---|---|
| `URL` | yes | | Absolute `http`/`https` URL, no user info, no fragment. The only address ever contacted. |
| `Format` | yes | | `scores` or `tei_predict` (`ParseFormat`). |
| `Threshold` | yes | | In `(0, 1]`. `score >= Threshold` triggers. |
| `Timeout` | yes | | `> 0`. Bounds one whole detection, all HTTP calls included. |
| `FailureMode` | yes | | `closed` or `open` (`ParseFailureMode`). No implicit default. |
| `ModelName` | no | `http-classifier` | Reported as `Assessment.Model`. |
| `MaliciousLabels` | no | `["MALICIOUS"]` | `tei_predict` only, case-insensitive. |
| `MaxResponseBytes` | no | 1 MiB | Larger bodies fail. |
| `ChunkRunes` | no | 510 | Minimum 16. |
| `ChunkOverlapRunes` | no | `min(64, ChunkRunes/4)` | At most `ChunkRunes/4`. |
| `BatchSize` | no | 32 | Chunks per HTTP call (TEI's default `max_client_batch_size`). |
| `MaxChunks` | no | 256 | Per detection; larger inputs fail instead of being truncated. |

## Wire contracts

Both formats use `POST <URL>` with `Content-Type: application/json` and
require a `2xx` response with a single JSON value. Unknown response fields are
ignored; trailing data, `null` scores and non-numeric scores are rejected.
Every score must be a finite number in `[0, 1]`.

### `scores`

Contract defined by this package, for a thin custom sidecar.

```json
{"texts": ["first chunk", "second chunk"]}
```

```json
{"scores": [0.02, 0.97]}
```

`scores` has exactly one entry per text, in order; any other length is an
error.

### `tei_predict`

Hugging Face Text Embeddings Inference `POST /predict` on a sequence
classification model.

```json
{"inputs": [["first chunk"], ["second chunk"]], "raw_scores": false, "truncate": false}
```

```json
[
  [{"label": "BENIGN", "score": 0.03}, {"label": "MALICIOUS", "score": 0.97}],
  [{"label": "BENIGN", "score": 0.99}, {"label": "MALICIOUS", "score": 0.01}]
]
```

- Each text is sent as a one-element array. TEI reads a bare list of two
  strings as one *(query, text)* pair and a list of one-element or two-element
  arrays as a batch, so a batch of texts must never be sent as `["a", "b"]`.
- The response must be an array with one array of `{label, score}` per input.
  The flat single-input form is rejected.
- `raw_scores: false` returns probabilities (not logits); `truncate: false`
  makes TEI reject an over-long input (HTTP 413/422) instead of silently
  dropping its tail, which would hide part of the text from the classifier.
- A text scores the maximum `score` among the predictions whose `label` is in
  `MaliciousLabels` (case-insensitive). A row without any configured label is
  an `invalid_response` error, never a score of 0, so a wrong label mapping
  cannot silently disable the guardrail. Scores of other labels are still
  range-checked.

### Label mapping for Prompt Guard 2

Prompt Guard 2 (22M and 86M) is a binary classifier: `BENIGN` or `MALICIOUS`.
Its model card shows the `MALICIOUS` name; a sidecar whose checkpoint lacks
`id2label` exposes `LABEL_0` (benign) and `LABEL_1` (malicious) instead. Check
the labels the sidecar actually returns and set `MaliciousLabels` to match,
for example `[]string{"LABEL_1"}`. A multilabel model can list several labels;
the highest of them wins.

## Chunking

Prompt Guard 2 has a 512-token context window and the model card tells
callers to split longer inputs and scan the segments. The package has no
tokenizer, so it estimates conservatively: **at most one token per rune**, and
two tokens are reserved for the special tokens. A chunk of at most 510 runes
therefore stays inside the window for any text; for English prose it uses
roughly a quarter of it, which costs extra calls but never leaves a gap.

- Texts are split on rune boundaries (never inside a UTF-8 sequence; invalid
  bytes become U+FFFD). Boundaries prefer a position after whitespace within
  the last quarter of the window, then a position that does not split a
  combining sequence, ZWJ sequence or emoji modifier, then a hard cut.
- Consecutive chunks overlap by `ChunkOverlapRunes`, so any phrase of at most
  that many runes lies entirely inside at least one chunk. Longer phrases are
  seen in several overlapping parts; this is the usual sliding-window trade-off.
- Every rune of every text is covered. Empty and whitespace-only texts are not
  sent. Texts and chunks are scored independently; the assessment score is the
  maximum over all of them, and `classifier_top_text_index` is the index (in
  the input slice) of the text holding it. All chunks are always scored, so
  the reported score is the true maximum rather than a partial one.
- Input needing more than `MaxChunks` chunks fails with `too_many_chunks`.
  It is never truncated and nothing is sent.
- The estimate is the only protection against over-long inputs on the client
  side; if the sidecar still rejects one, that surfaces as a `status` failure.

## Assessment

| Field | Value |
|---|---|
| `Score` | Maximum score over all chunks of all texts, `0` when nothing was scanned. |
| `Triggered` | `Score >= Threshold`. A score equal to the threshold triggers. |
| `Reason` | Fixed text when triggered, empty otherwise. Never contains input text. |
| `Model` | `ModelName`. |
| `Metadata` | `classifier_format`, `classifier_chunks`, `classifier_threshold`, `classifier_top_text_index` (when something was scanned). |

## Failures

A failure is returned as `*httpclassifier.Error` with a stable `Kind`:

| Kind | Cause |
|---|---|
| `canceled` | The caller's context was cancelled or its deadline passed. |
| `timeout` | `Config.Timeout` elapsed. Unwraps to `context.DeadlineExceeded`. |
| `transport` | Connection, TLS or request-building error. |
| `status` | Non-2xx status, redirects included (never followed). `Error.Status` has the code. |
| `response_too_large` | Body larger than `MaxResponseBytes`. |
| `invalid_response` | Invalid or trailing JSON, wrong shape, missing/null field, wrong number of scores, no configured label. |
| `invalid_score` | Score that is NaN, infinite or outside `[0, 1]`. |
| `too_many_chunks` | Input needs more than `MaxChunks` chunks. |

`FailureMode` decides what the caller sees:

- `closed`: the `*Error` is returned with an empty assessment. Callers never
  get a successful assessment when no score was produced. The current
  `SemanticPromptInjectionGuardrail` turns it into HTTP 502.
- `open`: `error` is `nil` and the assessment is
  `{Triggered: false, Score: 0, Reason: "HTTP classifier unavailable; failing open."}`
  with `Metadata["classifier_degraded"] == true` and
  `Metadata["classifier_failure"]` set to the kind. Wiring code must surface
  that marker (log, finding or metric); it is never a silent success.
- A cancelled or expired **caller** context (`canceled`) is returned as an
  error in both modes: nobody is waiting for the answer. The classifier's own
  timeout is a normal failure subject to the mode.

Fail-open lets an attacker who can make the sidecar fail (or can craft input
exceeding `MaxChunks`) bypass this detector. Prefer `closed` unless
availability matters more than coverage.

Errors and metadata never contain input text, response content or the
endpoint URL: messages hold only the kind and the HTTP status code.

## Network behavior

- One request per batch of at most `BatchSize` chunks, sequential, within one
  `Timeout` budget shared by the whole detection.
- No implicit retry. A failed call is a failure; retries, if wanted, belong to
  the caller.
- Redirects are not followed and proxy environment variables are ignored, so
  the configured URL is the only host contacted.
- No authentication header is sent: the sidecar is expected on a private
  network or behind a local proxy. Adding one is a wiring-level decision.

## Licensing note for operators

This repository ships and downloads no model weights. Llama Prompt Guard 2 is
distributed by Meta under the Llama 4 Community License (the model card's
`license_name: llama4`). Whoever deploys the sidecar must accept that license,
obtain access to the gated Hugging Face repository and comply with its terms
(attribution notice, acceptable use policy, additional terms for very large
services). Nothing in this package grants or implies those rights.

## Sources

- TEI `/predict` schema: [`docs/openapi.json`](https://github.com/huggingface/text-embeddings-inference/blob/main/docs/openapi.json)
  (`PredictRequest`, `PredictInput`, `Prediction`, `PredictResponse`).
- TEI input handling (`[string]` / `[[string], [string, string]]` batch rules)
  and response shapes: [`router/src/http/types.rs`](https://github.com/huggingface/text-embeddings-inference/blob/main/router/src/http/types.rs).
- Llama Prompt Guard 2 model card:
  [meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
  and [22M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M)
  (binary benign/malicious classification, 512-token context window, advice to
  split longer inputs, license). The cards are gated; their text was read from
  a public mirror, so verify the label names against your own checkpoint.
