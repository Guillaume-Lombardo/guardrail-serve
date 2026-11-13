# Semantic sidecar: French and original-corpus evaluation (L11)

Versioned summary of one measurement of **Llama Prompt Guard 2 86M** (the default),
the previous default **DeBERTa** (kept as a fallback) and, as a smoke measurement,
**Prompt Guard 2 22M**, all on the same corpora with the same protocol. Raw per-case
rows and logs are not versioned: they stay in the working directory of the run on the
build host.

Built with Llama.

**Verdict.**

- The 86M model removes almost all of the false positives DeBERTa produced
  (French injection corpus: 4 false positives instead of 27; original corpus: 0
  instead of 36) but, at the predefined threshold `0.9`, it also finds far fewer
  attacks on its own (11/31 on the French injection corpus, 8/13 on the original
  corpus). Combined with the deterministic detector it adds **one** true positive
  and **4** false positives on the French injection corpus, and nothing on the
  original corpus.
- The mode rule fixed before the measurement was: switch the semantic detector to
  `block` only if the French false-positive rate is at most 5% **and** recall does
  not drop below 29/31 (French injection) and 6/6 (original French). Recall holds
  (30/31 and 6/6) but the French FPR is **16.1%** (5/31), so the example policies
  stay in **`annotate`** for the semantic detector. The 86M default stands either
  way: it is the better model on every false-positive measure.
- DeBERTa reproduces the L10 figures exactly (same counts as the previous report),
  which makes the two reports comparable. Its only advantage is semantic recall at
  the cost of a false-positive rate of 87% (French injection) and 52% (original).
- Prompt Guard 2 22M is faster (p50 80 ms against 164 to 172 ms) and smaller, but
  finds fewer attacks (5/31, then 2/6 and 4/7) and is no better on false positives
  once combined with the deterministic detector. It stays a configurable option, not
  the default.

## Provenance

| Item | Value |
| --- | --- |
| Run | 13/11/2026, 19:55 to 20:07 (Europe/Paris), one model after the other: 86M 19:55 to 20:00, DeBERTa 20:00 to 20:05, 22M 20:05 to 20:07. Read-only: no versioned file changed, corpus and baseline hashes identical before and after each run |
| Service under test | checkout at `eac5f59` (branch `feat/prompt-guard-2` on top of `main`), throwaway loopback binary built without CGO, `GOMAXPROCS=2`, real `POST /v1/guardrails/{policy}` API, `SEMANTIC_ENABLED=true`, format `scores`. Four policies per run: deterministic only, semantic only, both, both in audit |
| Sidecar | image built from the same checkout through Compose-equivalent build arguments, run offline, 2 CPU / 2 GiB, 2 torch threads, `SIDECAR_VERIFY_LABELS=true`; torch 2.9.1+cpu, transformers 4.57.6, tokenizers 0.22.2 |
| 86M | `meta-llama/Llama-Prompt-Guard-2-86M` at `a8ded8e697ce7c355e395a0df51f94adb4a2fd27`, safetensors sha256 `e72017db…5f6b09`, labels `LABEL_0`/`LABEL_1`, malicious = `LABEL_1`, image `sha256:c81641a4f958` |
| DeBERTa | `protectai/deberta-v3-base-prompt-injection-v2` at `90c9989b1a342275dd0d1a95aad283c04e075671`, sha256 `6521cb8d…0424`, labels `SAFE`/`INJECTION`, malicious = `INJECTION`, image `sha256:b99798c66f76` |
| 22M | `meta-llama/Llama-Prompt-Guard-2-22M` at `11614a155199674a0a95e6602d6ab0417b790ed0`, sha256 `5120e30b…5fa1`, malicious = `LABEL_1`, image `sha256:ff071438cd38` |
| Threshold | `0.9`, fixed before any measurement, identical for the three models. Not tuned, not chosen on these corpora |
| Host | `codex-dev`, 4 vCPU VM shared with other agents (load 1 up to 4.5 during the 86M run, 4.1 DeBERTa, 3.1 22M). Latencies are on the pessimistic side and noisy |
| Timeouts | `SEMANTIC_TIMEOUT=10s`, `SEMANTIC_FAILURE_MODE=closed`. No error, no timeout, no degraded warning in any of the runs |
| Protocol | sequential, one request in flight, keep-alive; 3 repetitions with rotated mode and corpus order; 6 warmup texts per mode, reported apart; detections identical across the 3 repetitions; service decisions equal the direct sidecar score at `>= 0.9` for every case |
| Detection definition | presence of a `prompt_injection` (deterministic) or `semantic_prompt_injection` finding. A non-200 status or a transport error is never counted as TP, FP, TN or FN (there were none) |

Sets are never pooled across corpora or languages. Filters are applied at read time;
corpus files are unchanged.

- **A**: `french-injection-v1`, 62 cases (31 positives, 31 negatives).
- **B**: French cases of `original-v1`, 39 cases (6 positives, 33 negatives; the
  negatives include texts with secrets or PII, labelled `prompt_injection=false`).
- **C**: English cases of `original-v1`, 44 cases (7 positives, 37 negatives).
- **G**: the whole original corpus (B and C), 83 cases, reported as the global figure.

## Results at threshold 0.9

TP / FP / TN / FN, with recall and false-positive rate (FPR).

### A. French injection corpus (31 positives, 31 negatives)

| Model | Mode | TP | FP | TN | FN | Recall | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| none | deterministic | 29 | 1 | 30 | 2 | 93.5% | 3.2% |
| **86M** | semantic | 11 | 4 | 27 | 20 | 35.5% | 12.9% |
| **86M** | deterministic + semantic | 30 | 5 | 26 | 1 | 96.8% | 16.1% |
| DeBERTa | semantic | 30 | 27 | 4 | 1 | 96.8% | 87.1% |
| DeBERTa | deterministic + semantic | 31 | 27 | 4 | 0 | 100% | 87.1% |
| 22M | semantic | 5 | 2 | 29 | 26 | 16.1% | 6.5% |
| 22M | deterministic + semantic | 29 | 3 | 28 | 2 | 93.5% | 9.7% |

### B. Original corpus, French (6 positives, 33 negatives)

| Model | Mode | TP | FP | TN | FN | Recall | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| none | deterministic | 6 | 0 | 33 | 0 | 100% | 0% |
| **86M** | semantic | 3 | 0 | 33 | 3 | 50.0% | 0% |
| **86M** | deterministic + semantic | 6 | 0 | 33 | 0 | 100% | 0% |
| DeBERTa | semantic | 6 | 24 | 9 | 0 | 100% | 72.7% |
| DeBERTa | deterministic + semantic | 6 | 24 | 9 | 0 | 100% | 72.7% |
| 22M | semantic | 2 | 0 | 33 | 4 | 33.3% | 0% |
| 22M | deterministic + semantic | 6 | 0 | 33 | 0 | 100% | 0% |

### C. Original corpus, English (7 positives, 37 negatives)

| Model | Mode | TP | FP | TN | FN | Recall | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| none | deterministic | 7 | 1 | 36 | 0 | 100% | 2.7% |
| **86M** | semantic | 5 | 0 | 37 | 2 | 71.4% | 0% |
| **86M** | deterministic + semantic | 7 | 1 | 36 | 0 | 100% | 2.7% |
| DeBERTa | semantic | 7 | 12 | 25 | 0 | 100% | 32.4% |
| DeBERTa | deterministic + semantic | 7 | 13 | 24 | 0 | 100% | 35.1% |
| 22M | semantic | 4 | 0 | 37 | 3 | 57.1% | 0% |
| 22M | deterministic + semantic | 7 | 1 | 36 | 0 | 100% | 2.7% |

### G. Original corpus, global French + English (13 positives, 70 negatives)

| Model | Mode | TP | FP | TN | FN | Recall | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| none | deterministic | 13 | 1 | 69 | 0 | 100% | 1.4% |
| **86M** | semantic | 8 | 0 | 70 | 5 | 61.5% | 0% |
| **86M** | deterministic + semantic | 13 | 1 | 69 | 0 | 100% | 1.4% |
| DeBERTa | semantic | 13 | 36 | 34 | 0 | 100% | 51.4% |
| DeBERTa | deterministic + semantic | 13 | 37 | 33 | 0 | 100% | 52.9% |
| 22M | semantic | 6 | 0 | 70 | 7 | 46.2% | 0% |
| 22M | deterministic + semantic | 13 | 1 | 69 | 0 | 100% | 1.4% |

The combination evaluates both detectors, with no short-circuit, and is the union of
the two. An audit-mode policy produced the same detections as the combined policy and
never changed a decision.

What changes, by case (86M, combined against deterministic only):

- **A**: gains `frinj-pos-031` (a known deterministic false negative); loses four
  negatives to false positives (`frinj-neg-001`, `002`, `005`, `027`). It misses 20
  of the 31 attacks on its own (`frinj-pos-002`, `003`, `004`, `006` to `012`, `015`
  to `020`, `022` to `024`, `030`); the deterministic detector catches nearly all of
  them.
- **B, C**: no change from the deterministic detector. The semantic detector alone
  finds 3/6 French and 5/7 English attacks and flags no legitimate text, including
  the texts with secrets or PII that DeBERTa flagged (24 of 33 in French).

## Score separation without a threshold (diagnostic only)

The threshold was not selected from these numbers. They only show whether a
different threshold could change the picture. AUC computed on the direct sidecar
scores, one text per call:

| Set | 86M | DeBERTa | 22M |
| --- | ---: | ---: | ---: |
| A French injection | 0.79 | 0.70 | 0.63 |
| B original, French | 1.00 | 0.88 | 0.78 |
| C original, English | 1.00 | 0.99 | 0.96 |

Recall / FPR on set A for other thresholds (86M): 19/31 and 6/31 at 0.01, 15/31 and
5/31 at 0.1, 12/31 and 5/31 at 0.5, 11/31 and 4/31 at 0.9. No threshold reaches the
deterministic detector's recall at an acceptable false-positive rate on this corpus,
so the verdict does not depend on the threshold choice; this table is not a
recommendation to change `0.9`.

## Latency

Client to Go service to sidecar and back, sequential, ms, 3 repetitions pooled
(n = 186 on A, 117 on B, 132 on C).

| Mode | 86M p50 / p95 | DeBERTa p50 / p95 | 22M p50 / p95 |
| --- | --- | --- | --- |
| deterministic | 0.3 / 0.6 | 0.3 / 0.8 | 0.3 / 0.7 |
| semantic | 164 to 172 / 204 to 208 | 164 to 176 / 204 to 208 | 80 / 96 to 104 |
| deterministic + semantic | 164 to 172 / 196 to 204 | 164 to 176 / 204 to 221 | 80 / 96 to 101 |

The range spans the three sets. The 86M and DeBERTa models have the same backbone
size, hence the same latency; the 22M model is about twice as fast. With 2
concurrent clients (the default `HTTP_MAX_CONCURRENT_REQUESTS`), p50 is about 268 ms
for the 86M model (62 requests in 8.6 s), 277 to 292 ms for DeBERTa and 92 ms for
22M, as inference is serialized.

Resources over the run (sidecar limited to 2 CPU / 2 GiB):

| Model | Sidecar CPU mean / max | Sidecar memory mean / max | Go RSS max |
| --- | --- | --- | --- |
| 86M | 153% / 196% | 962 / 1025 MiB | 30.6 MiB |
| DeBERTa | 154% / 203% | 673 / 732 MiB | 29.2 MiB |
| 22M | 110% / 189% | 462 / 504 MiB | 29.6 MiB |

The 86M model needed about 290 MiB more memory than DeBERTa in this run; the Compose run with the real 86M peaked at 1247 MiB under the 2 GiB
limit, including model load.

Readiness took 3.6 to 4.4 s from container start (weights are in the image).

## Recommendation

1. Keep the semantic detector **disabled** by default.
2. If you enable it, set `semantic_prompt_injection` to `annotate` and keep
   `prompt_injection` (deterministic) on `block`. The shipped
   [example policies](../../examples/semantic/policies/policies.yaml) do this.
   The 86M model is a useful second opinion that rarely cries wolf; it is not a
   substitute for the deterministic rules on French input.
3. A policy that sets the semantic detector to `block` stays possible. With the 86M
   model expect about 16% false positives on French injection-style negatives and
   about 1 in 3 French attacks detected by the model alone. Rule order does not
   rescue a semantic `block` combined with `detect_secret` set to `mask`: a block
   takes precedence and a blocked request is refused whole, never partly redacted.
4. To go from `annotate` to `block` on French input, the false-positive rate must be
   re-measured (target: 5% or less on French) together with a threshold chosen on a
   separate calibration set. That work is out of scope here.

## Limits

- Small samples (31, 6 and 7 positives): indicative figures, no confidence
  intervals. One threshold, short texts (single chunk), no long-text load in the
  evaluation (see the sidecar README for those timings).
- The corpora are public and synthetic. The repository's `prompt_injection` label
  excludes secrets and PII, so a model that flags them is counted as a false
  positive. The reasons for the 86M model's low recall on the French injection
  corpus (language, phrasing, corpus style) were not investigated here.
- The three runs share a noisy VM and were done one after the other, so latencies
  are indicative and not strictly comparable to those of the previous report
  (different host load, different image); the DeBERTa run is the control that
  matches the previous L10 counts.
- The sidecar's own per-chunk latency measured for long texts in the README
  (about 200 ms per 510-character chunk, on French text) differs from the older
  figure of 125 ms per chunk in the previous report: the texts, the load and the
  tokenizer vocabulary are not the same, so the two are not comparable.
- The 22M figures are a smoke measurement of the option (same protocol, one run),
  not a recommendation.
