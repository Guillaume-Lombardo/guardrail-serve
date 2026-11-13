# Semantic sidecar: French evaluation report

Versioned summary of one measurement of the default English model on the French
corpora merged with ADR 0018. Raw per-case rows and logs are not versioned: they
stay in the working directory of the run on the build host.

**Verdict.** At the predefined threshold `0.9`, the default model adds 2 true
positives on the French injection corpus and 26 false positives. It is **not**
suitable as a French blocking detector. The deterministic detector alone is
better on every French set measured here. Use the sidecar, if at all, with the
semantic detector set to `annotate` and the deterministic detector set to
`block` (see "Recommendation"). The model is an English model: its quality on
French is a documented limit of this deployment, not an API bug, and no
replacement model is proposed here.

## Provenance

| Item | Value |
| --- | --- |
| Run | 13/11/2026, 09:51 to 10:04 (Europe/Paris), read-only: no versioned file changed, corpus and baseline hashes identical before and after |
| Service under test | `main` at `d756fc3680fc3c9c788fe17f5d264eb5f9b415e9` (L9 merged), throwaway loopback binary, `GOMAXPROCS=2`, real `POST /v1/guardrails/{policy}` API, `SEMANTIC_ENABLED=true`, format `scores` |
| Sidecar | image built from head `857e02c` (`guardrail-serve-semantic-sidecar:l10-857e02c`, id `sha256:37e24489a2f5…`), not rebuilt for this run; torch 2.9.1+cpu, transformers 4.57.6, 2 torch threads, offline |
| Model | `protectai/deberta-v3-base-prompt-injection-v2`, revision `90c9989b1a342275dd0d1a95aad283c04e075671`, safetensors sha256 `6521cb8d…0424`, labels `SAFE`/`INJECTION` |
| Threshold | `0.9`, fixed before any measurement. Not tuned, not chosen on these corpora |
| Host | `codex-dev`, 4 vCPU shared VM (load 1.0 before, up to 3.35 during), sidecar limited to 2 CPU / 2 GiB. Latencies are on the pessimistic side |
| Timeouts | `SEMANTIC_TIMEOUT=10s`, `SEMANTIC_FAILURE_MODE=closed`; no error or timeout in about 2 000 requests |
| Protocol | sequential, one request in flight, keep-alive; 3 repetitions with rotated mode and corpus order; 6 warmup texts per mode, reported apart; detections identical across the 3 repetitions |
| Detection definition | presence of a `prompt_injection` (deterministic) or `semantic_prompt_injection` finding. A non-200 status or transport error is never counted as TP/FP/TN/FN |

Sets are never pooled. Filters are applied at read time; corpus files are
unchanged.

- **A**: `french-injection-v1`, 62 cases (31 positives, 31 negatives).
- **B**: French cases of `original-v1`, 39 cases (6 positives, 33 negatives; the
  negatives include texts with secrets or PII, labelled
  `prompt_injection=false`).
- **C**: English cases of `original-v1`, 44 cases (7 positives, 37 negatives), a
  control showing the model works in its own language.

## Results at threshold 0.9

| Set | Mode | TP | FP | TN | FN | Recall | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A French injection | deterministic | 29 | 1 | 30 | 2 | 93.5% | 3.2% |
| A French injection | semantic | 30 | 27 | 4 | 1 | 96.8% | 87.1% |
| A French injection | deterministic + semantic | 31 | 27 | 4 | 0 | 100% | 87.1% |
| B original, French | deterministic | 6 | 0 | 33 | 0 | 100% | 0% |
| B original, French | semantic | 6 | 24 | 9 | 0 | 100% | 72.7% |
| B original, French | deterministic + semantic | 6 | 24 | 9 | 0 | 100% | 72.7% |
| C original, English (control) | deterministic | 7 | 1 | 36 | 0 | 100% | 2.7% |
| C original, English (control) | semantic | 7 | 12 | 25 | 0 | 100% | 32.4% |
| C original, English (control) | deterministic + semantic | 7 | 13 | 24 | 0 | 100% | 35.1% |

The combination evaluates both detectors, with no short-circuit, and is the
union of the two.

What changes, by case:

- **A**: the semantic detector catches `frinj-pos-030` and `frinj-pos-031`, the two
  known deterministic false negatives, and misses `frinj-pos-017`, which the
  deterministic detector catches. It has 27 false positives: 26 new ones plus the
  `frinj-neg-011` it shares with the deterministic detector; only `frinj-neg-016`,
  `021`, `024` and `031` stay negative.
  Score separation without a threshold is weak (AUC 0.70, diagnostic only, not used
  to choose the threshold): negatives have a median score of 1.0, so another
  threshold would not repair it.
- **B**: no gain (the 6 positives are already detected). The 24 false positives are
  the texts with secrets or PII, the two responses and three negatives.
- **C**: the model works in English (AUC 0.99, positives at least 0.9999) yet still
  flags 12 negatives, mostly texts with secrets, PII or responses. Part of the
  problem is class definition (injection versus sensitive content), not only
  language.

## Latency

Client to Go service to sidecar and back, sequential, ms, 3 repetitions pooled
(n = 186 on A, 117 on B, 132 on C).

| Mode | p50 | p95 |
| --- | ---: | ---: |
| deterministic | 0.3 | 0.6 |
| semantic | 166 to 176 | 208 to 220 |
| deterministic + semantic | 164 to 180 | 200 to 224 |

The range spans the three sets. The sidecar called directly gives p50 164 to 172 ms.
With 2 concurrent clients (the default `HTTP_MAX_CONCURRENT_REQUESTS`), p50 is about
276 to 283 ms and 62 requests take 8.6 to 9.0 s instead of about 11 s, as inference
is serialized. Sidecar CPU averaged 154% (peak 198% of a 200% ceiling), memory
averaged 856 MiB (peak 900 MiB); the Go service peaked at 29.6 MiB RSS.

## Recommendation

1. Keep the semantic detector **disabled** by default.
2. If you enable this model, set `semantic_prompt_injection` to `annotate` and keep
   `prompt_injection` (deterministic) on `block`. The shipped
   [example policies](../../examples/semantic/policies/policies.yaml) do this.
3. A policy that sets the semantic detector to `block` stays possible and
   configurable, but expect a high false-positive rate on French input and on any
   text containing credentials or personal data. Rule order does not rescue it: a
   semantic `block` stage combined with `detect_secret` set to `mask` blocks every
   text the model calls an injection (for example `password=…`) instead of masking
   it, regardless of the order of the detector steps within the same evaluated
   stage (input and output are evaluated separately), in enforce mode, because a
   block takes precedence. A blocked request is refused whole, never partly
   redacted.
4. For French blocking, a multilingual or French-tuned model would have to be
   evaluated on the same corpora, with a threshold chosen on a separate calibration
   set. That work is out of scope here.

## Limits

- Small samples (31, 6 and 7 positives): indicative figures, no confidence
  intervals. One model, one threshold, short single-chunk texts, no long-text load
  (see the sidecar README for those).
- The corpora are public and synthetic. The repository's `prompt_injection` label
  excludes secrets and PII, so a model that flags them is counted as a false
  positive.
- Shared VM, so latencies are pessimistic; the sidecar image predates the
  micro-batch refactor and Compose changes of this PR, so its latency applies to the
  validated image only.
- The functional cross-check of the same run (suites, offline gate on both corpora,
  LiteLLM plus the real sidecar, 44 assertions) was green. One initial attempt
  failed because the model blocked `password=…` before masking, which is the
  behavior described in point 3, not a product defect.
