# ADR 0019: Real semantic sidecar

## Status

Accepted. Validated with the real model on the build host, including French corpus quality (see `deploy/semantic-sidecar/EVALUATION.md`); the Compose stack at the final head remains pending (see "Validation status").

## Context

ADR 0010 and ADR 0016 ship the Go HTTP classifier client and its policy
adapter. Both are proven only against `httptest` fakes: no real model has ever
answered a request. The first planned model, Llama Prompt Guard 2 (22M/86M), is
gated on Hugging Face and published under the Llama 4 Community License. This
change delivers a deployable, configurable sidecar, its documentation and
reproducible checks, without touching the Go service's domain code.

## Decision

### Server: a small Python service, not TEI

- Hugging Face Text Embeddings Inference was evaluated first because it would
  need no custom code. Its documentation lists only CamemBERT and XLM-RoBERTa as
  supported sequence-classification architectures
  ([supported models](https://github.com/huggingface/text-embeddings-inference/blob/main/docs/source/en/supported_models.md)).
  Both candidate models are DeBERTa-family (ProtectAI: `DebertaV2ForSequenceClassification`;
  Prompt Guard 2: mDeBERTa-based per Meta's documentation). TEI support is
  therefore unverified, and nothing could be run to verify it on the allowed
  host. Rejected for now; the Go `tei_predict` format remains available for
  operators who verify a TEI deployment themselves.
- `deploy/semantic-sidecar` is a Python 3.13 service: standard-library HTTP
  server, `transformers` + CPU `torch` loaded lazily. It speaks the existing
  `scores` contract on `POST /classify` (`{"texts": [...]}` ->
  `{"scores": [...]}`), so the Go client and policy code are unchanged.
- Rejected: FastAPI/uvicorn (extra dependencies for three routes), ONNX Runtime
  (a second export path to validate), in-process Go inference (CGO, weights in
  the binary).

### Model: configurable, with an explicit fallback

- Target: Llama Prompt Guard 2 86M or 22M. It is gated. A Hugging Face token
  was looked for in the `Agents` 1Password vault by item title, category and tag
  only (item contents were never read); none exists. By instruction, no
  credential was created or requested and the work did not stop. The default
  therefore falls back to
  [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2).
- Default model facts, read from the model repository (not assumed):

  | Property | Value |
  | --- | --- |
  | License | Apache-2.0, not gated |
  | Pinned revision | `90c9989b1a342275dd0d1a95aad283c04e075671` |
  | Weights | `model.safetensors`, sha256 `6521cb8d...b6e0424` (checked at build) |
  | Labels (`id2label`) | `0: SAFE`, `1: INJECTION` |
  | Context window | 512 positions |
  | Language | English only (model card) |
  | Known limits | Does not detect jailbreaks; model card advises against system prompts (false positives); upstream project archived |

  The vendor's published metrics (95.25% accuracy, 99.74% recall, 91.59%
  precision on 20,000 untrained prompts) are on their data, in English. They say
  nothing about this repository's corpus, notably its French cases.
  **Do not read them as results for guardrail-serve.**
- Prompt Guard 2 is a drop-in configuration, not a default: set
  `MODEL_ID`/`MODEL_REVISION` to the commit the operator verified, supply a
  build-time token as a BuildKit secret, and set
  `SIDECAR_MALICIOUS_LABELS=MALICIOUS` (its documented label; verify against
  the checkpoint's `id2label`). The operator accepts the Llama license, which
  also governs any image that bakes the weights in. No revision is pinned here
  because the gated repository could not be read.
- Model, revision, labels and limits are configuration. Any model other than
  the default must give its labels explicitly and a full commit hash. Labels are
  checked against the checkpoint's `id2label` at load time: an unknown label, an
  ambiguous label set or a set covering every class aborts startup, so a wrong
  mapping cannot silently disable detection. A model's threshold stays in the Go
  service (`SEMANTIC_THRESHOLD`); the sidecar returns probabilities and does not
  threshold. The malicious probability of several labels is their sum (softmax
  outputs are exclusive).

### Safety and robustness

- No `trust_remote_code`, safetensors only (`use_safetensors=True`), fast
  tokenizer required, build-time download restricted to weights, tokenizer and
  config files (no pickle, ONNX or code files).
- The model is downloaded once at image build at a pinned commit and baked in.
  Runtime is offline (`HF_HUB_OFFLINE=1`), needs no token and no egress. A build
  token is a BuildKit secret: never an argument, environment variable, layer,
  log line or commit. Python base image pinned by digest; Python packages
  hash-pinned (`pip --require-hashes`, CPU-only torch wheel).
- Bounded: body size, texts per request, tokens per text, requests in flight
  (excess gets 503 `overloaded`), open connections, socket timeouts and a
  per-request inference deadline (504). The deadline is cooperative: a forward pass
  cannot be interrupted, so it is observed between micro-batches and once before
  responding, and the overrun is bounded by one micro-batch (measured: 16.3 s for a
  10 s deadline with 32 texts of 512 tokens). It is not a hard guarantee.
  Inference is serialized; a request waiting past its deadline gets 503 `busy`.
  The client's timeout is not propagated: an inference already running continues
  after the client gave up, and queued requests are served unless their own
  deadline passes first. A process-killing or cancellation mechanism was not added.
- Token limit: the Go client's 510-rune chunk is a heuristic (ADR 0010). The
  sidecar tokenizes with the real tokenizer and rejects, never truncates, a text
  above `SIDECAR_MAX_TOKENS` (422 `text_too_long`), which the client reports as
  a `status` failure under its configured failure mode. The heuristic is not
  presented as a token guarantee. The Go client is unchanged: no defect was
  proven in it.
- Output validation: the number of scores must match the number of texts and
  every score must be finite and in [0, 1] (float noise within 1e-6 clamped);
  otherwise 500 `backend_error`.
- Logs and errors: one JSON line per request with id, route, status, duration
  and text count. No input text, header, token, URL query or exception message
  is logged or returned; exceptions are reported by class name only.
- Non-root (uid 65532), read-only root filesystem, dropped capabilities,
  memory/CPU/pid limits in the compose file, liveness `GET /healthz`, readiness
  `GET /readyz` (200 only after the model is loaded and warmed up), a bounded
  graceful shutdown (below), fail-fast exit on model load failure.
- Shutdown: on SIGTERM/SIGINT the server stops admitting requests (new and
  keep-alive requests get 503 `shutting_down`, the listening socket is closed),
  waits for the requests in flight, and exits 0. The wait is capped by
  `SIDECAR_SHUTDOWN_GRACE_SECONDS` (default 20 s: above the worst total
  duration observed for a request, 16.5 s, which is the 10 s cooperative deadline plus
  an overrun of about 6.5 s for the micro-batch in flight; this covers what was
  observed, not every CPU or batch size), and
  the Compose `stop_grace_period` (25 s) stays above it. Handler threads remain
  daemon threads and the wait is a bounded count of active requests, not a join: an
  unbounded wait on a stuck backend or a stalled client would outlast the container
  stop timeout and be killed anyway. Requests still running at the cap are cut and
  logged (`drain_timeout`).
- No sidecar authentication, consistent with ADR 0010: the sidecar publishes no
  port in the compose file and must stay on a private network. The compose file
  attaches it only to a network declared `internal: true` (no route outside the
  stack; the runtime is offline and needs none), while the guardrail service joins
  both that network and the default one. A plain `docker run` on the default bridge
  was observed to allow outbound connections, which motivated this isolation. Host
  firewall and service configuration are not touched.

### Verification layout

- `deploy/semantic-sidecar/tests`: stdlib `unittest` against a fake backend
  (server bounds, strict parsing, output validation, log hygiene, config and
  label mapping).
- `tests/integration/semantic_sidecar`: the Go client, and the Go service
  end to end, against the real Python server code with the fake backend (always
  run when `python3` exists). A build-tagged test (`realsidecar`) targets a
  running sidecar with the real model; it is excluded from GitHub CI.
- `deploy/semantic-sidecar/tests/test_shutdown.py`: shutdown contract on a real
  server process with a file-gated fake backend (deterministic, no Docker).
- `deploy/semantic-sidecar/tools/measure.py`: corpus-independent recall, FPR
  and latency reproducer (see `EVALUATION.md` for the run on the shared corpora).

## Validation status

Real-model validation ran on the build host (`codex-dev`) at head `857e02c`
(report kept by the orchestrator); the sidecar code changed afterwards only as
described under "Changes after validation".

- **Validated**: image build (model downloaded at the pinned commit, safetensors
  sha256 matches), model load and readiness (3.6-4.3 s), labels `SAFE`/`INJECTION`
  and score = probability of `INJECTION`, the `scores` contract and its negative
  cases, the 512-token limit (a text of 510 `a` characters accepted, 511 rejected with 422 and not truncated; the token count of those probes was not recorded), container
  hardening (uid 65532, read-only root, dropped capabilities, offline, memory and CPU
  limits), the Go test `TestRealModel`, and the Go service against the sidecar
  (attack blocked; fail-closed 502 and fail-open warning). Latency is about 125 ms per
  510-character chunk on 2 shared vCPUs, linear, inference serialized (figures in the
  sidecar README). English only.
- **Compose stack, run on the build host at `75cd4d4`** (images rebuilt at that
  SHA; 103 of 104 assertions): `depends_on` with `service_healthy`, the
  `internal: true` network (egress from the sidecar blocked, a control on the default
  network open), hardening, the contract with the real model, the guardrail API in
  front of it, long texts and timeouts, `compose restart`, a real crash restarted by
  `unless-stopped`, and the guardrail's own SIGTERM drain. The one failure was
  real: on SIGTERM the sidecar exited in about 0.9 s and cut an in-flight request
  (`RemoteDisconnected` about 0.4 s after the signal), because
  `daemon_threads=True` and `serve()` closed the server without waiting for the
  handlers. Earlier statements that SIGTERM was graceful had not been tested.
  Fixed by the bounded drain above, with process-level regression tests (SIGTERM
  during a parked request; admission stopped; blocked backend and stalled client
  bounded by the grace).
- **`integration_pending`**: the targeted Docker retest of the sidecar's graceful
  stop on the final head (`docker compose stop`/`kill -TERM` with a request in
  flight).
- **French quality, measured** after L9 merged (`main` at `d756fc3`, threshold `0.9`
  fixed beforehand, sequential, 3 repetitions; provenance and limits in
  [`EVALUATION.md`](../../deploy/semantic-sidecar/EVALUATION.md)). On the 62-case
  French injection corpus: deterministic 29 TP / 1 FP / 30 TN / 2 FN, semantic 30 / 27
  / 4 / 1, both combined 31 / 27 / 4 / 0. On the French cases of the original corpus
  the model adds 24 false positives and no true positive. Neither threshold nor corpus
  was changed to hide this.
- Timeout findings: with the Go default `SEMANTIC_TIMEOUT=2s` a 12 000-character text
  fails (502 in fail-closed mode); the earlier Compose default of `5s` fails at
  19 000 characters. `MAX_TEXT_CHARS=20000` needs at least 8-10 s at low load, more
  under concurrency; the Compose default is now `10s`. The Go default is left
  unchanged (ADR 0010/0016 behavior).
- A request abandoned by the client appeared to keep the sidecar busy (a benign call
  took 3.19 s instead of 0.16 s after three timeouts). That is an inference from
  timings, not confirmed from logs.

### Changes after validation

The micro-batch loop moved into a backend-independent function so the cooperative
deadline is unit-tested with a simulated clock, and the compose file gained the
internal network and the 10 s default. The Compose run above found the SIGTERM
defect; the shutdown drain, `SIDECAR_SHUTDOWN_GRACE_SECONDS` and the compose
`stop_grace_period` were added afterwards and need the targeted retest listed above.

## Consequences

- Positive: a real, auditable path from the Go service to a model; failure
  behavior covered by black-box tests; model choice is configuration; no change
  to domain code or the Go client.
- Negative: a Python runtime and a large CPU image (3.03 GB measured, PyTorch plus
  baked weights) to operate; CPU latency for a base-size model exceeds the 2 s default
  client timeout above roughly 12 000 characters (measured), and serialized inference
  makes latency grow with concurrency; the English-only default model flags
  most French negatives (87.1% FPR at `0.9` on the French injection corpus) for two
  extra true positives, so it must not be the French blocking detector. The
  recommended operator policy is deterministic `block` plus semantic `annotate`; the
  semantic detector stays disabled by default. An explicit semantic `block` remains
  configurable, and, within the same evaluated stage and regardless of step order (enforce mode), it takes precedence over a secret `mask`, so texts that look like
  credentials are blocked rather than redacted. This is a model limit, not an API
  defect; a multilingual or French-tuned model would need the same evaluation with a
  separately calibrated threshold.
- Risks: the upstream default model is archived (no fixes); fail-open lets an
  attacker who can degrade the sidecar bypass the detector (default stays
  `closed`); amd64/CPython 3.13 only for the hash-locked wheels; Prompt Guard 2
  adds license obligations the operator owns.

## Alternatives considered

- Stock TEI: see above; unverified architecture support.
- Download the model at container start: rejected, it needs egress and a token
  at runtime and makes startup depend on an external service.
- Mutable revision (`main`): rejected, a model update would silently change
  detection results.
- Chunk and aggregate inside the sidecar with the real tokenizer: deferred. It
  would make long inputs exact, but duplicates the client's windowing; revisit if
  measurements show the heuristic rejects legitimate inputs.
