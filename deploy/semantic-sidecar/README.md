# Semantic sidecar

A small, bounded HTTP service that runs a prompt-injection classifier on CPU
and speaks the `scores` contract of the Go
[HTTP classifier](../../internal/semantic/httpclassifier/README.md). Design and
rationale: [ADR 0019](../../docs/adr/0019-real-semantic-sidecar.md); model choice,
label mapping and licensing: [ADR 0020](../../docs/adr/0020-llama-prompt-guard-2.md).

> **Built with Llama.** The default model, Llama Prompt Guard 2 86M, is distributed by
> Meta under the Llama 4 Community License. Llama 4 is licensed under the Llama 4
> Community License, Copyright © Meta Platforms, Inc. All Rights Reserved. An image
> built here contains those weights: read "Llama license and distribution" below
> before sharing one. This repository ships no weights.

> **Validation status.** Validated with the real models on the build host (`codex-dev`,
> 13/11/2026, head `eac5f59`): image build with a BuildKit secret, offline load of the
> 86M, 22M and DeBERTa checkpoints, label mapping and the load-time canary, the `scores`
> contract, token limits, the Compose stack with container hardening, the bounded drain
> on `SIGTERM` (peak memory 1247 MiB under the 2 GiB limit), the Go `TestRealModel`, and
> the evaluation on the French injection corpus and the original corpus. Earlier L10
> validations of the server (fail-closed 502, fail-open warning, graceful stop) are
> unchanged by this model switch. At threshold `0.9` the 86M model adds one true
> positive and four false positives to the deterministic detector on the French
> injection corpus, so the example policies keep it in `annotate`. See
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
([`sidecar.env.template`](sidecar.env.template)); [`profiles/`](profiles) holds the
pinned alternatives. The revision is always a full commit hash and the weights'
sha256 is verified at build. Labels are checked against the checkpoint at startup,
and a canary check refuses a model whose mapping is inverted (see "Label mapping").

| Model | License | Gated | Attack label | Revision | `model.safetensors` sha256 | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| [`meta-llama/Llama-Prompt-Guard-2-86M`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) (**default**) | Llama 4 Community License | yes | `LABEL_1` (`LABEL_0` = benign) | `a8ded8e697ce` | `e72017dbbe89` | mDeBERTa-v3-base, multilingual (Meta evaluated English, French, German, Hindi, Italian, Portuguese, Spanish, Thai), binary, 512 tokens, 1.1 GB of weights. |
| [`meta-llama/Llama-Prompt-Guard-2-22M`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M) (`profiles/prompt-guard-2-22m.env`) | Llama 4 Community License | yes | `LABEL_1` | `11614a155199` | `5120e30bcd53` | DeBERTa-v3-xsmall, English pretraining: Meta documents a larger gap on multilingual text. 283 MB of weights. |
| [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) (`profiles/deberta-fallback.env`) | Apache-2.0 | no | `INJECTION` (`SAFE` = benign) | `90c9989b1a34` | `6521cb8d0ac0` | Previous default and fallback: English only; no jailbreak detection; avoid on system prompts; upstream archived. |

Two more models are bench candidates only, with build arguments in [`bench/`](bench)
and no supported profile ([ADR 0023](../../docs/adr/0023-semantic-model-bench.md),
[EVALUATION.md](EVALUATION.md)):

| Model | License | Gated | Attack label | Revision | `model.safetensors` sha256 | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| [`qualifire/prompt-injection-sentinel`](https://huggingface.co/qualifire/prompt-injection-sentinel) (`bench/sentinel.env`) | Elastic License 2.0 | yes | `jailbreak` (`benign`) | `e24131782819` | `fcba2fec67d9` | ModernBERT-large, English training data, not evaluated on other languages by its authors. ELv2 allows commercial use but forbids offering it to third parties as a hosted or managed service ([`notices/qualifire-sentinel.txt`](notices/qualifire-sentinel.txt)). The stock image loads it only with `USER` set in the container (torch inductor). |
| [`Qwen/Qwen3Guard-Gen-0.6B`](https://huggingface.co/Qwen/Qwen3Guard-Gen-0.6B) (`bench/qwen3guard-gen-0.6b.env`) | Apache-2.0 | no | category `Jailbreak` | `fada3b2f655b` | `4f3ce47ebd96` | Generative safety model (Qwen3, 0.6B): the stock backend cannot serve it; `bench/qwen3guard.py` runs it on the unchanged server with prompt moderation, greedy decoding and a strict parse, score 1.0 iff `Jailbreak` is listed. |

Thresholds belong to the Go service (`SEMANTIC_THRESHOLD`, default `0.9`); the
sidecar returns probabilities. Calibrate the threshold per model on your own
data. Vendor metrics are not a calibration.

### Label mapping

Both Prompt Guard 2 checkpoints are **binary** (benign / malicious) and their
`config.json` has **no `id2label`**: transformers names the classes `LABEL_0` and
`LABEL_1`. The model card's example comments the output as `MALICIOUS`, which the
checkpoint does not contain (an earlier version of these docs repeated it).
`LABEL_1` is the malicious class (checked on the real model, ADR 0020), so the
default is `SIDECAR_MALICIOUS_LABELS=LABEL_1` and the score is the softmax
probability of `LABEL_1`. A checkpoint with several attack classes (for example
benign / injection / jailbreak) is configured by listing every attack label; their
probabilities are summed. At load time the sidecar also scores one canary attack
and one canary benign text and aborts if the attack is below 0.5 or the benign text
is not below it (`SIDECAR_VERIFY_LABELS=false` turns this off for a model that is not
meant to flag the canary); this catches an inverted mapping, not poor quality.

## Build and run

Docker builds belong on the designated build host (not on docker-box).

```sh
# Default model (Prompt Guard 2 86M, gated): the token is a BuildKit secret, never an
# argument or environment of the image. Read it from your secret store in the build
# shell only (never type the value: it would persist in shell history) and do not write
# it to a file in the repository. The account needs access to the gated repository.
HF_TOKEN="$(<secret-store read command>)" \
  docker compose -f deploy/semantic-sidecar/compose.yaml up --build

# 22M option or public fallback: pinned profiles (the fallback needs no token)
docker compose -f deploy/semantic-sidecar/compose.yaml \
  --env-file deploy/semantic-sidecar/profiles/prompt-guard-2-22m.env up --build
docker compose -f deploy/semantic-sidecar/compose.yaml \
  --env-file deploy/semantic-sidecar/profiles/deberta-fallback.env up --build
```

Without Compose, pass the token as a BuildKit secret file or pipe it, for example
`docker build --secret id=hf_token,src=<file outside the repository, mode 0600> ...`
or `... | docker build --secret id=hf_token,src=/dev/stdin ...`. An absent or empty
token still builds a public model; the gated default then fails with a sanitized
message. The build verifies the `model.safetensors` sha256 against the pinned value
and prints it. Any other model must give its own full commit hash, sha256 and labels.

Runtime facts: non-root (65532), read-only root filesystem, capabilities
dropped, no published port, memory limit 2 GB / 2 CPUs, offline
(`HF_HUB_OFFLINE=1`), `HEALTHCHECK` on `/readyz`. Memory observed on `codex-dev` with
the DeBERTa fallback under these limits: 365-530 MiB idle, 1.29 GiB peak under maximum
load; see "Measured results and limits" for Prompt Guard 2 86M.

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
| `SIDECAR_MODEL_ID` | `meta-llama/Llama-Prompt-Guard-2-86M` | Hub id (used only without `SIDECAR_MODEL_PATH`). |
| `SIDECAR_MODEL_REVISION` | pinned for the default | Full lowercase 40-hex commit; required for other models without a local path. |
| `SIDECAR_MODEL_PATH` | empty | Local snapshot directory (set to `/models/model` in the image). |
| `SIDECAR_MALICIOUS_LABELS` | `LABEL_1` | Comma-separated, case-insensitive attack classes; required for non-default models (the DeBERTa fallback uses `INJECTION`). |
| `SIDECAR_VERIFY_LABELS` | `true` | Load-time canary: refuse to start if one canary attack does not score >= 0.5 or one canary benign text does not score < 0.5. |
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
case observed was 16.5 s in total with DeBERTa in L10 (an overrun of about 6.5 s past the
10 s deadline, for 32 texts of 512 tokens at batch 8) and 17.8 s with the 86M model in L11 on
a loaded VM, so the `20` default covers what was observed but with little margin. It is
not a universal guarantee: slower CPUs or larger batches overrun more. **Keep the container stop
timeout above the grace period**: the Compose file sets `stop_grace_period: 25s`;
with plain `docker run`, pass `--stop-timeout 25` (Docker's default is 10 s, which
would cut the longest requests). If you raise the inference deadline or the batch
size, raise both values. Events on stderr: `draining`, `stopped_accepting`, then
`drained` or `drain_timeout`.

## Llama license and distribution

Read from the checkpoints at the pinned revisions (the `LICENSE` file, identical for
the 86M and 22M repositories, sha256 `73755cee…2917`): the **Llama 4 Community
License Agreement**, effective April 5, 2025, plus the Llama 4 Acceptable Use Policy
(`USE_POLICY.md`). The model repository's metadata says `license: other`,
`license_name: llama4`. Summary of what it asks of someone who **distributes or makes
available** the weights or a product containing them (this is not legal advice; the
license text prevails):

| Obligation | How this deployment meets it |
| --- | --- |
| Give recipients a copy of the agreement | The download keeps `LICENSE` and `USE_POLICY.md`; the image carries them in `/models/model/`. |
| Keep the attribution notice in a "Notice" text file | `notices/llama4.txt` is copied to `/models/NOTICE` ("Llama 4 is licensed under the Llama 4 Community License, Copyright © Meta Platforms, Inc. All Rights Reserved."). The repository `NOTICE` has the same text. |
| Display "Built with Llama" on a related website, user interface, blog post, about page or product documentation | This README, the root README and ADR 0020 state it; the image label `io.guardrail-serve.model.attribution` carries it. An operator who exposes a product built on this image must display it in their own documentation or interface. |
| Comply with the Acceptable Use Policy and applicable law | Operator responsibility. |
| Name any AI model trained or improved with Llama outputs "Llama ..." | Not applicable: nothing is trained or fine-tuned here. |
| A separate license from Meta is required in the 700-million-monthly-active-users case (conditions on the licensee and its affiliates, measured as the agreement defines) | Operator responsibility: read the commercial terms of the agreement; they are not restated here. |

Using the weights requires the operator's own Hugging Face account to have been granted
access to the gated repositories (a license acceptance made by that account). No image
is published from this project and no weights are in this repository; whoever pushes or
shares an image built from here becomes the distributor and owns these obligations. The
repository's MIT license does not apply to the weights. The fallback model is Apache-2.0
and carries no Llama obligation (`profiles/deberta-fallback.env` swaps the notice).

## Measured results and limits

Measured on `codex-dev` (2 vCPU, `SIDECAR_TORCH_THREADS=2`, 2 GiB limit, a VM
shared with other agents, so figures are on the pessimistic side) with the image
built from head `eac5f59`, 13/11/2026, French text (a repeated 510-character
sentence). Few repetitions for the large batches (n = 3-4). These are single-host
latency figures, not a capacity guarantee.

| Workload sent to `/classify` | 86M p50 | 86M p95 / max | 22M p50 | DeBERTa p50 |
| --- | --- | --- | --- | --- |
| 1 short text (30 characters, n=15) | 115 ms | 159 ms | 30 ms | 106 ms |
| 1 chunk of 510 characters (n=15) | 263 ms | 302 ms | 89 ms | 275 ms |
| 4 chunks | 899 ms | 974 ms | 299 ms | 876 ms |
| 8 chunks | 1604 ms | 2046 ms | 604 ms | 1671 ms |
| 16 chunks | 3148 ms | 3455 ms | 1169 ms | 3296 ms |
| 32 chunks (largest client batch) | 6509 ms | 6718 ms | 2269 ms | 6929 ms |
| 1 text at the token limit (399 words) | 1105 ms | - | 313 ms (401 words) | 827 ms (299 words) |
| 32 texts at the token limit (worst case) | - | 504 after 17.8 s | 504 after 12.2 s | 504 after 16.3 s |

That is about 200 ms per 510-character chunk for the 86M model (about 70 ms for the
22M model), linear. The earlier L10 figure of 125 ms per chunk (DeBERTa, English
text, a quieter VM, another image) is **not comparable**: the texts, the load and the
tokenizer differ, and the DeBERTa column above, measured now with the same script,
is close to the 86M column. Size `SEMANTIC_TIMEOUT` from the current columns.

Other results: ready 3.6 to 4.4 s after start; the 86M labels are
`LABEL_0`/`LABEL_1` (no `id2label` in the checkpoint), score = probability of
`LABEL_1`, confirmed by the load-time canary and by the Go test; mapping the
malicious class to `LABEL_0` makes the sidecar refuse to start, and naming a label
`MALICIOUS` fails at load; `TestRealModel` passes with `SEMANTIC_SIDECAR_FRENCH=1`
(benign text about 0.0004, attacks 0.998 to 0.9996, a 7-chunk text in 920 ms);
token and length limits (511 characters rejected with 422, no truncation) are the
server's, not the model's, and are covered by the unit tests. Inference is serialized
(two concurrent clients: 268 ms p50 for 62 requests in 8.6 s, no error). Memory:
about 1 GiB resident during the evaluation (peak 1025 MiB), 1247 MiB at the peak of
the Compose run including model load.

The earlier L10 measurements on DeBERTa for the Go service (closed/open behaviour,
`SEMANTIC_TIMEOUT` outcomes for 6 000, 12 000 and 19 000 characters) were not
re-run: they depend on the server and the client, not on the model, but the time
per chunk has changed (see above), so the break-even text sizes move with it.

French and original-corpus quality was measured separately (threshold `0.9`, same
protocol for the three models): [EVALUATION.md](EVALUATION.md) has the tables,
provenance and limits. In short, with the 86M model the sidecar alone finds 11 of the
31 French injection attacks (4 false positives out of 31) and, combined with the
deterministic detector, 30/31 with 5 false positives; on the original corpus it adds
nothing and flags nothing. About 170 ms p50 per sequential request through the Go
service.

Not validated: other CPUs or higher concurrency, other thresholds, other models than
the three above.

### Choosing `SEMANTIC_TIMEOUT` for your text limit

`SEMANTIC_TIMEOUT` bounds the scan of **one text**, all chunk batches included.
`MAX_TEXT_CHARS` (default `20000`) is counted across all texts of a request and
chunks advance by about 446 characters (510 minus the 64 overlap), so a
20 000-character text is about 45 chunks, around 9 s of CPU with the 86M model at the
measured 200 ms per chunk (L11 figure, extrapolated from 32 chunks in 6.5 s; the older
5.6 s estimate was DeBERTa on a quieter host), plus overhead, split over two calls.

- The Go default `2s` suits short chat messages only (up to about 10 chunks, 5 000
  characters). It already failed at 12 000 characters, so with
  `MAX_TEXT_CHARS=20000` legitimate long texts become 502 in fail-closed mode.
- To accept the full default limit, `SEMANTIC_TIMEOUT` must exceed about 9 s at low
  load, so the Compose default of `10s` leaves almost no margin and a loaded sidecar
  will time out on the largest texts: use **15 s or more**, or lower
  `MAX_TEXT_CHARS`. (The default is unchanged by L11; the DeBERTa model had the same
  per-chunk cost in the same measurement.)
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
  chunks, about 6.5 s at low load with the 86M model) and includes the wait for the inference slot.
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
a 10 s deadline answered 504 after 16.3 s with DeBERTa (L10) and after 17.8 s with the
86M model (L11), two micro-batches of about 8 s. Typical
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
head `eac5f59`, all steps passed with the real 86M image. The HF token comes from
your secret store and goes through a pipe, never a command-line argument:

```sh
# build (token on stdin of the BuildKit secret; nothing is written to disk)
<secret-store read command> | docker build --secret id=hf_token,src=/dev/stdin \
  -t guardrail-serve-semantic-sidecar:local deploy/semantic-sidecar
docker run --rm -d --name semantic-sidecar-check -p 127.0.0.1:18080:8080 \
  --read-only --tmpfs /tmp:size=64m --cap-drop ALL --security-opt no-new-privileges \
  guardrail-serve-semantic-sidecar:local
# wait for GET http://127.0.0.1:18080/readyz to return 200, then:
SEMANTIC_SIDECAR_URL=http://127.0.0.1:18080 SEMANTIC_SIDECAR_FRENCH=1 \
  go test -tags realsidecar ./tests/integration/semantic_sidecar -run TestRealModel -count=1 -v
docker stop semantic-sidecar-check
```

`TestRealModel` is excluded from `go test ./...` and from GitHub CI. It checks
readiness, real label mapping, French samples (with `SEMANTIC_SIDECAR_FRENCH=1`) and
that a long multi-chunk text is accepted, and logs scores and elapsed time.

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
- Model: pinned commit and verified `model.safetensors` sha256 (table in "Models").

## Tests

```sh
python3 -I -m unittest discover -s deploy/semantic-sidecar/tests -t deploy/semantic-sidecar/tests
go test ./tests/integration/semantic_sidecar/...
```

The fake backend lives in `tests/` and is never copied into the image.
`tests/test_shutdown.py` starts the real server process (`run_fake_server.py` runs the
production `serve()`, signal handlers included) with a file-gated fake backend and
checks the shutdown contract deterministically; it needs no Docker and no model.
