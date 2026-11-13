# Semantic sidecar

A small, bounded HTTP service that runs a prompt-injection classifier on CPU
and speaks the `scores` contract of the Go
[HTTP classifier](../../internal/semantic/httpclassifier/README.md). Design and
rationale: [ADR 0019](../../docs/adr/0019-real-semantic-sidecar.md).

> **Validation status.** Validated with the real model on the build host
> (`codex-dev`, head `857e02c`): image build, model load, label mapping, the
> `scores` contract, token limits, container hardening, the Go service against the
> sidecar (fail-closed 502, fail-open warning) and the latencies below.
> The Compose stack was run on the build host at head `75cd4d4` (103 of 104
> assertions): `depends_on`/readiness, the `internal: true` network (egress blocked),
> hardening, the contract with the real model, the guardrail API, timeouts and
> restarts. The one failure, the sidecar cutting in-flight requests on SIGTERM, is
> fixed by the bounded drain in "Shutdown". The targeted Docker retest at
> `5945c07` validated in-flight completion, closed admission and bounded shutdown;
> process-level tests also cover the drain with a fake backend. The default model is
> English only and was measured on the French corpora: at threshold `0.9` it adds 2
> true positives and 26 false positives on the French injection corpus, so it is
> not suitable as a French blocking detector (use `annotate`). See
> [EVALUATION.md](EVALUATION.md) and "Measured results and limits".

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
| 504 | `timeout` | The deadline (`SIDECAR_INFERENCE_TIMEOUT_SECONDS`) had passed when a micro-batch ended. It is cooperative, not a hard cut-off: see "Deadline semantics". |

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
dropped, no published port, memory limit 2 GB / 2 CPUs, offline
(`HF_HUB_OFFLINE=1`), `HEALTHCHECK` on `/readyz`. Observed on `codex-dev` with
these limits: 365-530 MiB idle, 1.29 GiB peak under maximum load.

Network isolation (Compose): the sidecar is attached only to a `sidecar` network
declared `internal: true`, so it has no route outside the stack; the `guardrail`
service joins both that network and the default one to publish its port. This
matters because a container on the default bridge could open outbound
connections (observed from a plain `docker run`), which the runtime never needs.
The Compose stack was run on the build host at `75cd4d4` and the sidecar could not
reach the Internet there. To verify it yourself after `up`, for example use
`docker compose -f deploy/semantic-sidecar/compose.yaml exec semantic-sidecar python -c "import urllib.request as u; u.urlopen('https://1.1.1.1', timeout=3)"`,
which must fail. A standalone `docker run` (used for validation) is on the
default bridge and not isolated; add `--network none` if you do not need to
publish a port. No host firewall or service configuration is changed by this
change.

Wire the Go service with `SEMANTIC_URL=http://semantic-sidecar:8080/classify`,
`SEMANTIC_FORMAT=scores`.

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
| `SIDECAR_INFERENCE_TIMEOUT_SECONDS` | `10` | Cooperative deadline from request start (queue wait + inference), observed between micro-batches only. |
| `SIDECAR_BATCH_SIZE` | `8` | Texts per forward pass. The deadline overrun is bounded by one micro-batch, so a smaller value shortens it (throughput effect not measured). |
| `SIDECAR_TORCH_THREADS` | `0` | PyTorch intra-op threads (`0` keeps the default). |
| `SIDECAR_SHUTDOWN_GRACE_SECONDS` | `20` | Upper bound on how long SIGTERM/SIGINT waits for in-flight requests (see "Shutdown"). |

### Shutdown

On SIGTERM or SIGINT the sidecar:

1. **stops admitting** requests: new requests, including those on an idle keep-alive
   connection, get `503 {"error":"shutting_down"}` and `Connection: close`, and the
   listening socket is closed so no new connection is accepted;
2. **lets in-flight requests finish** normally (a request being read, queued for the
   inference lock or running inference), answering them with `Connection: close`;
3. exits `0` once none is left (`drained`), or after at most
   `SIDECAR_SHUTDOWN_GRACE_SECONDS` (`drain_timeout` logged with the number of
   requests cut). Idle keep-alive connections never delay the exit.

The drain covers one sidecar HTTP request, not an entire Go analysis. Analyses
that require multiple classifier batches can have their next batch refused
during shutdown. The Go service applies its configured failure mode: sanitized
502 when fail-closed, or degraded pass-through when fail-open.

The wait is bounded on purpose: the handler threads stay daemon threads, so a
stuck backend or a client that stalls inside its body cannot hold the process
beyond the grace period (an unbounded join could outlive the container stop timeout and
end in SIGKILL anyway). The bound is sized from the cooperative inference deadline:
a request already running at SIGTERM ends at its cooperative deadline
(`SIDECAR_INFERENCE_TIMEOUT_SECONDS`) plus the micro-batch that was in flight. The worst
case observed was 16.5 s in total (an overrun of about 6.5 s past the 10 s deadline, for
32 texts of 512 tokens at batch 8), so the `20` default covers what was observed. It is
not a universal guarantee: slower CPUs or larger batches overrun more. **Keep the container stop
timeout above the grace period**: the Compose file sets `stop_grace_period: 25s`;
with plain `docker run`, pass `--stop-timeout 25` (Docker's default is 10 s, which
would cut the longest requests). If you raise the inference deadline or the batch
size, raise both values. Events on stderr: `draining`, `stopped_accepting`, then
`drained` or `drain_timeout`.

## Measured results and limits

Measured on `codex-dev` (2 vCPU, `SIDECAR_TORCH_THREADS=2`, 2 GiB limit, a VM
shared with other agents, so figures are on the pessimistic side) with the image
built from head `857e02c`, model revision `90c9989b1a34`, English text. Few
repetitions for the large batches (n = 2-4). These are single-host latency
figures, not a capacity guarantee.

| Workload sent to `/classify` | p50 | p95 / max |
| --- | --- | --- |
| 1 short text (30 characters) | 120 ms | 146 ms |
| 1 chunk of 510 characters (n=15) | 209 ms | 236 ms |
| 1 text of 512 tokens | 977 ms | 1328 ms |
| 4 chunks | 532 ms | 599 ms |
| 8 chunks | 1005 ms | 1298 ms |
| 16 chunks | 1981 ms | 1993 ms |
| 32 chunks (largest client batch) | 4018 ms | 4154 ms |
| 32 texts of 512 tokens (worst case) | - | 504 after 16.3 s |

That is about 125 ms per 510-character chunk, linear. Other results: ready 3.6-4.3 s
after start; labels `SAFE`/`INJECTION` confirmed, score = probability of
`INJECTION`, order-independent; a text of 510 `a` characters accepted, 511 rejected with 422
(`text_too_long`, no truncation); a 510-rune CJK chunk is rejected (422), 510
emoji are accepted; the Go test `TestRealModel` and the Go service passed
(`SEMANTIC_TIMEOUT=2s`, closed: attack blocked in 0.18 s, 6 000 characters in
1.84 s, **12 000 characters 502**; `5s`: 12 000 characters 200 in 3.48 s,
**19 000 characters 502**; closed with a 50 ms timeout returns 502 with no URL or
text; open returns 200 and logs `semantic classifier degraded`). Six parallel
8-chunk requests: two got 503 (`SIDECAR_MAX_INFLIGHT=4`), the other four were
served one after another in 1.3-4.1 s: **inference is serialized**, about 8
chunks per second in total.

French corpus quality was measured separately (threshold `0.9`, same image):
[EVALUATION.md](EVALUATION.md) has the table, provenance and limits. In short, the
model adds 2 true positives and 26 false positives on the 62-case French injection
corpus, and about 170 ms p50 per sequential request through the Go service.

Not validated: the Docker retest of the graceful stop after the fix described in
"Shutdown", other CPUs or higher concurrency, other models or thresholds.

### Choosing `SEMANTIC_TIMEOUT` for your text limit

`SEMANTIC_TIMEOUT` bounds the scan of **one text**, all chunk batches included.
`MAX_TEXT_CHARS` (default `20000`) is counted across all texts of a request and
chunks advance by about 446 characters (510 minus the 64 overlap), so a
20 000-character text is about 45 chunks, around 5.6 s of CPU on the measured
host plus overhead, split over two calls.

- The Go default `2s` suits short chat messages only (up to about 10 chunks, 5 000
  characters). It already failed at 12 000 characters, so with
  `MAX_TEXT_CHARS=20000` legitimate long texts become 502 in fail-closed mode.
- To accept the full default limit, use **at least 8-10 s at low load**
  (`SEMANTIC_TIMEOUT=10s`, the Compose default), or lower `MAX_TEXT_CHARS`. The 5 s
  of the previous Compose default failed at 19 000 characters.
- Recalibrate under your real concurrency. A text waits for every request ahead of
  it because inference is serialized: with `HTTP_MAX_CONCURRENT_REQUESTS=2` (the Go
  default) a maximum-size request can wait for another maximum-size one, so size
  the timeout for roughly `concurrent requests x chunks x per-chunk time` on your
  hardware, with margin, and measure p95 with `tools/measure.py`.
- Keep `HTTP_WRITE_TIMEOUT` (default `30s`) above the worst whole-request time and
  the LiteLLM-side guardrail timeout above that. Texts are scanned one after
  another, each with its own `SEMANTIC_TIMEOUT`: in fail-open mode a sidecar that
  hangs can make a request last up to `texts x SEMANTIC_TIMEOUT`, longer than the
  write timeout, so keep the sidecar healthy or use fail-closed.
- `SIDECAR_INFERENCE_TIMEOUT_SECONDS` applies to each HTTP call (at most 32
  chunks, about 4 s at low load) and includes the wait for the inference slot.
  Keep it at or below the client timeout so abandoned calls stop soon after the
  client gives up, and above the latency of one call under your concurrency.

`SEMANTIC_FAILURE_MODE`: fail-closed (default) turns a sidecar failure into HTTP
502; fail-open passes the text and logs `semantic classifier degraded`. Open lets
anyone who can degrade the sidecar bypass it. The Go service does not expose chunk
or batch sizes through the environment; the client defaults apply (510 runes, 32
chunks per call).

### Deadline semantics

The deadline is **cooperative, not a hard guarantee**. A forward pass already
running cannot be interrupted, so it is observed only between micro-batches
(`SIDECAR_BATCH_SIZE` texts each) and once more before the response. A
micro-batch that starts before the deadline runs to completion, so the overrun is
bounded by the duration of one micro-batch. Observed: 32 texts of 512 tokens with
a 10 s deadline answered 504 after 16.3 s (two micro-batches of about 8 s). Typical
client chunks (about 130 tokens) take about 1 s per micro-batch. A lower
`SIDECAR_BATCH_SIZE` shortens the worst-case overrun; its effect on throughput was
not measured, so the default stays `8`. The unit tests prove the cooperative
behavior with a simulated clock (`MicrobatchDeadlineTest`), not real timings.

### Abandoned requests

When the Go client times out or is cancelled, the sidecar is not told: an
inference already running continues until its micro-batch ends, and a request
waiting for the inference slot is still served unless its own deadline passes
first. The Go client does not retry, but an application that retries after a 502
adds work to a serialized sidecar. After three 502 on long texts, the next benign
call took 3.19 s instead of 0.16 s on the test host, which is consistent with
queueing behind abandoned work, but the sidecar logs were no longer available to
confirm it, so treat it as probable, not proven. Mitigation: size the timeout so
legitimate texts do not time out, and cap the number of concurrent callers.

## Validate with the real model

Run on the designated build host, never on docker-box. Last run: `codex-dev`,
head `857e02c`, all steps passed (plain `docker run`; the Compose stack was not
run):

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

The shared evaluation corpora are the ones summarized in [EVALUATION.md](EVALUATION.md);
that report came from a separate harness run on the build host that calls the Go
service, while this tool calls the sidecar directly (model-only latency, one score per
text). Report numbers from a new corpus with the commit, threshold, hardware, sample
size and repetitions, and never choose the threshold on the corpus you report.

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
`tests/test_shutdown.py` starts the real server process (`run_fake_server.py` runs the
production `serve()`, signal handlers included) with a file-gated fake backend and
checks the shutdown contract deterministically; it needs no Docker and no model.
