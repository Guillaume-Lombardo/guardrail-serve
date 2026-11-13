# Semantic sidecar

A small, bounded HTTP service that runs a prompt-injection classifier on CPU
and speaks the `scores` contract of the Go
[HTTP classifier](../../internal/semantic/httpclassifier/README.md). Design and
rationale: [ADR 0019](../../docs/adr/0019-real-semantic-sidecar.md).

> **Validation status: `integration_pending`.** The server, its limits and the
> wire contract are tested against a fake backend. The image has not been built
> and the real model has not been loaded or measured yet. Recall, false-positive
> rate, latency and a sound `SEMANTIC_TIMEOUT` are unknown until the steps in
> "Validate with the real model" are run.

## Contract

| Route | Purpose |
| --- | --- |
| `POST /classify` | `{"texts": ["..."]}` -> `{"scores": [0.01]}`. One attack probability in `[0, 1]` per text, in order. Only the `texts` key is accepted. |
| `GET /healthz` | Liveness: `200 {"status":"ok"}` while the process answers. |
| `GET /readyz` | Readiness: `200 {"status":"ready","model":"<id>@<rev12>"}` after the model is loaded and warmed up, `503 {"status":"loading"}` before. |

Errors are `{"error": "<code>"}` and never contain input, headers or paths:

| Status | Code | Meaning (Go client sees a `status` failure) |
| --- | --- | --- |
| 400 | `invalid_json`, `invalid_request`, `invalid_content_length`, `unsupported_transfer_encoding`, `incomplete_body` | Malformed request. Chunked bodies are refused. |
| 408 | `request_timeout` | Body not received in `SIDECAR_REQUEST_TIMEOUT_SECONDS`. |
| 411 / 413 / 415 | `length_required`, `body_too_large`, `unsupported_media_type` | Needs `Content-Length`, a body under `SIDECAR_MAX_BODY_BYTES`, and `application/json` (UTF-8). |
| 422 | `text_too_long` (with `index`), `invalid_text` | A text exceeds `SIDECAR_MAX_TOKENS` real tokens (never truncated), or is not valid Unicode. |
| 500 | `backend_error` | Model failure or invalid output (wrong count, NaN, outside `[0, 1]`). |
| 503 | `not_ready`, `overloaded`, `busy` | Loading, too many requests/connections in flight, or the inference slot was not free before the deadline. `Retry-After: 1`. |
| 504 | `timeout` | The deadline (`SIDECAR_INFERENCE_TIMEOUT_SECONDS`) passed between micro-batches. |

The client's rune chunking (510 runes) is a heuristic, not a token guarantee
(unusual Unicode can need more tokens than runes). The sidecar counts real
tokens and rejects over-long texts with 422 instead of truncating; with
`SEMANTIC_FAILURE_MODE=closed` that is a 502, with `open` a degraded pass.

## Models

Select the model by build arguments and `SIDECAR_*` variables
([`sidecar.env.template`](sidecar.env.template)). The revision is always a full
commit hash. Labels are checked against the checkpoint at startup.

| Model | License | Gated | Attack label | Notes |
| --- | --- | --- | --- | --- |
| [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) (default, rev `90c9989b1a34`) | Apache-2.0 | no | `INJECTION` (`SAFE` = benign) | English only; no jailbreak detection; avoid on system prompts; upstream archived. |
| [`meta-llama/Llama-Prompt-Guard-2-86M`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) / [`22M`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M) | Llama 4 Community License | yes | `MALICIOUS` (documented; verify against `id2label`) | Operator must accept the license and obtain access; the revision is not pinned here. A baked image carries the license obligations. |

Thresholds belong to the Go service (`SEMANTIC_THRESHOLD`, default `0.9`); the
sidecar returns probabilities. Calibrate the threshold per model on your own
data. Vendor metrics are not a calibration.

## Build and run

Docker builds belong on the designated build host (not on docker-box).

```sh
# Default model (no token needed)
docker compose -f deploy/semantic-sidecar/compose.yaml up --build

# Gated model: the token is a BuildKit secret, never an argument or environment of the image
export HF_TOKEN=...   # in your shell only; do not write it to a file in the repo
SIDECAR_MODEL_ID=meta-llama/Llama-Prompt-Guard-2-86M \
SIDECAR_MODEL_REVISION=<verified 40-char commit> \
SIDECAR_MODEL_SAFETENSORS_SHA256= \
SIDECAR_MALICIOUS_LABELS=MALICIOUS \
docker compose -f deploy/semantic-sidecar/compose.yaml -f deploy/semantic-sidecar/compose.gated.yaml up --build
```

The build prints the downloaded `model.safetensors` sha256; pin it in
`SIDECAR_MODEL_SAFETENSORS_SHA256` afterwards. The default model's hash is
pinned and verified.

Runtime facts: non-root (65532), read-only root filesystem, capabilities
dropped, no published port, memory limit 2 GB / 2 CPUs (adjust after
measuring), offline (`HF_HUB_OFFLINE=1`), `HEALTHCHECK` on `/readyz`.
Resource limits are starting points, not measured values. Wire the Go service
with `SEMANTIC_URL=http://semantic-sidecar:8080/classify`, `SEMANTIC_FORMAT=scores`.

Without Docker (development): `pip install` the hash-pinned requirements in a
CPython 3.13 virtual environment, download the snapshot with
`tools/download_model.py`, then
`SIDECAR_MODEL_PATH=<dir> PYTHONPATH=src python -m sidecar`.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIDECAR_HOST` / `SIDECAR_PORT` | `127.0.0.1` / `8080` | Bind address (the image sets `0.0.0.0`). |
| `SIDECAR_MODEL_ID` | default model | Hub id (used only without `SIDECAR_MODEL_PATH`). |
| `SIDECAR_MODEL_REVISION` | pinned for the default | Full lowercase 40-hex commit; required for other models without a local path. |
| `SIDECAR_MODEL_PATH` | empty | Local snapshot directory (set to `/models/model` in the image). |
| `SIDECAR_MALICIOUS_LABELS` | `INJECTION` | Comma-separated, case-insensitive; required for non-default models. |
| `SIDECAR_MAX_BODY_BYTES` | `1048576` | Largest accepted body. |
| `SIDECAR_MAX_TEXTS` | `32` | Texts per request (matches the client batch size). |
| `SIDECAR_MAX_TOKENS` | `512` | Real tokens per text incl. special tokens; cannot exceed the model's positions. |
| `SIDECAR_MAX_INFLIGHT` | `4` | Requests admitted at once; more get 503. |
| `SIDECAR_MAX_CONNECTIONS` | `32` | Open connections; more are refused with 503. |
| `SIDECAR_REQUEST_TIMEOUT_SECONDS` | `10` | Socket read timeout. |
| `SIDECAR_INFERENCE_TIMEOUT_SECONDS` | `10` | Deadline from request start (queue + inference). |
| `SIDECAR_BATCH_SIZE` | `8` | Micro-batch size; the deadline is checked between micro-batches. |
| `SIDECAR_TORCH_THREADS` | `0` | PyTorch intra-op threads (`0` keeps the default). |

Choosing the Go-side settings (`SEMANTIC_TIMEOUT`, `SEMANTIC_THRESHOLD`,
`SEMANTIC_FAILURE_MODE`):

- Keep the client timeout `<=` the sidecar deadline, and size it for a text of
  several chunks: a long text is scored in batches on CPU. Measure p95 first.
- Fail-closed (default) turns a sidecar failure into HTTP 502; fail-open passes
  the text and logs `semantic classifier degraded`. Open lets anyone who can
  degrade the sidecar bypass it.
- The Go service does not expose chunk or batch sizes through the
  environment; they use the client defaults (510 runes, 32 chunks per call).

## Validate with the real model

Run on the designated build host, never on docker-box:

```sh
docker compose -f deploy/semantic-sidecar/compose.yaml build semantic-sidecar
docker run --rm -d --name semantic-sidecar-check -p 127.0.0.1:18080:8080 \
  --read-only --tmpfs /tmp:size=64m --cap-drop ALL --security-opt no-new-privileges \
  -e SIDECAR_MALICIOUS_LABELS=INJECTION guardrail-serve-semantic-sidecar:local
# wait for GET http://127.0.0.1:18080/readyz to return 200, then:
SEMANTIC_SIDECAR_URL=http://127.0.0.1:18080 \
  go test -tags realsidecar ./tests/integration/semantic_sidecar -run TestRealModel -count=1 -v
docker stop semantic-sidecar-check
```

`TestRealModel` is excluded from `go test ./...` and from GitHub CI. It checks
readiness, real label mapping and that a long multi-chunk text is accepted, and
logs scores and elapsed time.

Recall, false-positive rate and latency on a labeled JSONL file (any corpus):

```sh
python3 deploy/semantic-sidecar/tools/measure.py \
  --url http://127.0.0.1:18080/classify --input <cases.jsonl> \
  --text-field text --label-field label --positive-values <attack,values> \
  --thresholds 0.5,0.8,0.9,0.95 --warmup 3
```

The shared evaluation corpus is owned by another change; run the reproducer on
it after that change merges and report the numbers then.

## Reproducibility

- Base image: `python:3.13-slim-trixie` pinned by digest in the `Dockerfile`.
- `requirements.txt`: exact versions with `sha256` hashes for CPython 3.13 on
  linux/amd64 (`pip install --require-hashes --only-binary=:all: --no-deps`);
  torch comes from the PyTorch CPU index (`torch==2.9.1+cpu`). Other platforms
  need a regenerated lock. To regenerate: resolve with
  `pip install --dry-run --report` for the direct set (`transformers`,
  `tokenizers`, `safetensors`, `huggingface-hub`, torch's pure-Python
  dependencies), take hashes from the report, and take the torch wheel hash from
  the PyTorch CPU index page.
- Direct pins: `transformers==4.57.6`, `tokenizers==0.22.2`,
  `huggingface-hub==0.36.2`, `safetensors==0.8.0`, `torch==2.9.1+cpu`.
- Model: pinned commit and verified `model.safetensors` sha256.

## Tests

```sh
python3 -I -m unittest discover -s deploy/semantic-sidecar/tests -t deploy/semantic-sidecar/tests
go test ./tests/integration/semantic_sidecar/...
```

The fake backend lives in `tests/` and is never copied into the image.
