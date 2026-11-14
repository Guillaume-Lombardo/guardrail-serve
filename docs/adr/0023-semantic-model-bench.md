# ADR 0023: Semantic model bench (frozen protocol, caching proxies)

## Status

Accepted. Builds on ADR 0011 (evaluation harness), ADR 0019 and 0020 (semantic sidecar,
Llama Prompt Guard 2), ADR 0021 (System One judge and cascade) and ADR 0022 (French
benchmark corpus). It adds a bench command and bench-only sidecar code; runtime code,
defaults, corpora, baselines and the offline gate are unchanged.

## Context

Choosing a semantic model, a threshold and a judge chain needs numbers that a reviewer
can trust and rebuild:

- the candidates (Prompt Guard 2 86M and 22M, ProtectAI DeBERTa v2, Qualifire
  Sentinel, Qwen3Guard-Gen-0.6B, the System One judge, the cascade) differ in output
  (probability, generated label, remote judgment) and in cost (CPU time, paid tokens);
- a threshold or gray zone tuned on the cases it is reported on overstates quality, and
  the 160-case test split of ADR 0022 is small enough that one adjustment after seeing
  it would bias the result;
- the judge is paid per input token and receives text: every call must be bounded,
  counted and masked, and no call may repeat;
- `guardrail-eval` (ADR 0011) scores a running service but cannot record classifier
  scores, replay them, or attribute a decision to a detector inside a chain.

## Decision

1. **A separate command, `cmd/guardrail-bench`**, not a mode of `guardrail-eval`. It
   imports `internal/app` and `internal/config` and serves the real handler in-process
   on `127.0.0.1:0` with a generated one-policy catalog: `bench-rules`
   (`prompt_injection`, block) or `bench-union` (`prompt_injection` and
   `semantic_prompt_injection`, block, both stages). The policy engine evaluates every
   step (no short-circuit), so one run gives the rules alone, the model alone and their
   union from the findings. Every service variable is cleared before a run and set from
   the run configuration only.
2. **Recording proxies between the service and its upstreams.** The sidecar proxy
   records each `/classify` answer and its upstream latency under
   sha256(`model@revision` + exact body) and can replay it, with or without the recorded
   delay; a replay miss is a 503, never an invented score. The System One proxy keys
   answers by sha256 of the exact masked request body (model version, question and
   fixed instructions included), so the judge alone and the cascade share one answer per
   text. Caches live outside Git (`~/.cache/guardrail-bench`) and hold scores, reduced
   answers and timings, never text.
3. **The real key never reaches the service.** The service holds a placeholder key and
   talks to the loopback proxy (`SYSTEMONE_BASE_URL=http://127.0.0.1:<port>`); the proxy
   reads the key from a file descriptor, adds it upstream, never logs it, never follows
   redirects or environment proxies and never echoes an upstream body. Its egress guard
   re-checks the masked text with independent patterns (e-mail, IBAN, card, French
   phone, IPv4, provider tokens, private keys, password assignments) and refuses to send
   a match: the case becomes an error, never a detection.
4. **Budget enforced before each paid call.** Cache-only mode cannot call upstream at
   all. Live mode caps calls (200) and cumulative cost (USD 1), checks the worst case of
   the next call (the documented 64k-token request maximum: billed tokens include a
   server-side overhead, so the body size is no bound) before sending, stops on 401 and
   after two consecutive 402/429, and appends a text-free ledger line per call.
5. **Protocol frozen from calibration, then enforced.** `calibrate` applies R1 (lowest
   threshold keeping rules ∪ model calibration false positives ≤ floor(5% × negatives),
   inclusive `>=`; model-alone fallback when the rules alone exceed it) and R2 (gray zone
   [L, U], U = the 86M R1 threshold, at most 25% of calibration texts inside, inclusive)
   and writes `protocol.json`, committed before any test run. Test runs read thresholds
   and zone from that file and refuse others (except 0.9, the current default, for the
   86M model); the judge refuses every corpus but `bench-test`; run files carry the
   protocol sha256 and the report refuses runs measured under another protocol.
6. **Generative guard models stay bounded.** Qwen3Guard-Gen runs on the unchanged sidecar
   server through a bench-only backend (`deploy/semantic-sidecar/bench/qwen3guard.py`):
   prompt moderation, greedy decoding, strict two-line parse, injection iff the category
   list contains `Jailbreak`, score 1.0 or 0.0. Malformed output is an error, not a score.
7. **Text-free, reproducible results.** Run files keep IDs, labels, decisions, scores,
   timings, token counts and host facts, never text. `export` bundles them,
   `report` computes counts, Wilson intervals, nearest-rank p50/p95, judge share, USD
   per 1000 requests, exact McNemar against rules + 86M at 0.9 and the D1 decision, and
   checks that each decision follows from its own records. The committed bundle,
   protocol, results, Markdown and chart rebuild with
   `deploy/semantic-sidecar/bench/reproduce-report.sh` without a model or a key.

## Consequences

- Measurements go through the code that serves production, including masking,
  chunking, thresholds, zone routing and failure modes; a bench result cannot come from
  a reimplementation.
- Each local model is inferred once per corpus and each text is judged once; recombining
  thresholds or rerunning the cascade costs no inference and no paid call.
- The bench sets process environment variables, so runs are sequential (concurrency 1)
  by construction.
- The egress guard is a second line of defense with its own false positives and gaps
  (names, postal addresses and free-form secrets are not checked); it does not replace
  the service masking, whose limits stay documented in `docs/detectors.md`.
- Live judge tests stay out of CI: the offline tests use fake upstreams only.

## Rejected alternatives

- **Extending `guardrail-eval`.** Its contract is a black-box HTTP client of a deployed
  service; adding replay, upstream attribution and paid-call budgets would mix two tools.
- **Calling the sidecar and System One directly from the bench.** Faster, but it would
  bypass masking, chunking and the cascade routing that the service actually applies.
- **Tuning thresholds on the test split or on the historical corpora.** Both are
  reported, never used for tuning: the historical corpora informed the rules (ADR 0018).
