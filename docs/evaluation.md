# Evaluation

Offline regression gate, versioned corpora, the semantic model bench and measured
results.

## Offline regression gate

Run the versioned FR/EN offline regression gate from the repository root:

```sh
scripts/eval-offline.sh
```

Provision the Go toolchain specified in `go.mod` and modules first (`go mod download`).
Evaluation itself disables Go downloads, uses the real service over an ephemeral
loopback HTTP listener, and requires no datasets, models, LLM, API key or `.env`.
A request failure or regression produces a nonzero test/process exit status.

The gate measures two versioned corpora, always separately (never pooled), and
the separate Evaluation workflow uploads the artifacts from `.agent-tmp/eval/`:

| Corpus | Baseline | Artifacts |
|---|---|---|
| `guardrail-serve-original-v1` (83 cases) | [`original-v1.json`](../tests/eval/baseline/original-v1.json) | `current.json`, `gate.json` |
| `guardrail-serve-french-injection-v1` (62 cases: 31 positives, 31 negatives) | [`french-injection-v1.json`](../tests/eval/baseline/french-injection-v1.json) | `french-injection-v1.current.json`, `french-injection-v1.gate.json` |

Each baseline pins the corpus hash and per-case detections; all known false
positives/negatives remain visible by case ID. Metrics below are rounded for
readability; gates use full precision.

Original corpus (83 cases), as measured by the current baseline (after
[ADR 0018](adr/0018-french-injection-recall.md)):

| Detector | Language | TP | FP | TN | FN | Precision | Recall | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| detect_pii | en | 8 | 2 | 34 | 0 | .800000 | 1 | .055556 |
| detect_pii | fr | 5 | 2 | 31 | 0 | .714286 | 1 | .060606 |
| detect_secret | en | 8 | 1 | 34 | 1 | .888889 | .888889 | .028571 |
| detect_secret | fr | 7 | 0 | 31 | 1 | 1 | .875000 | 0 |
| prompt_injection | en | 7 | 1 | 36 | 0 | .875000 | 1 | .027027 |
| prompt_injection | fr | 6 | 0 | 33 | 0 | 1 | 1 | 0 |

The six historical French injection cases are all detected (6/6) with no false
positive.

French prompt-injection corpus (62 cases, 31 positives and 31 negatives),
`prompt_injection`/`fr`:

| TP | FP | TN | FN | Recall | FPR |
|---:|---:|---:|---:|---:|---:|
| 29 | 1 | 30 | 2 | 93.5% | 3.2% |

The two false negatives (`frinj-pos-030`, `frinj-pos-031`) and the false
positive (`frinj-neg-011`) are kept as labelled known failures; see
[`tests/eval/README.md`](../tests/eval/README.md) for the corpus, the families and
the failure analysis. On both corpora the gate also enforces absolute French
floors for `prompt_injection`/`fr`: recall at least 85% and FPR at most 5%, both
defined (ADR 0018). These are deterministic-rule results only; they say nothing
about the optional semantic sidecar. Its separate measurements and limitations
are documented in [`deploy/semantic-sidecar/EVALUATION.md`](../deploy/semantic-sidecar/EVALUATION.md).

For every detector total and detector/language group, precision/recall must be
at least baseline and FPR at most baseline. Every previously correct case label
must remain correct: an improvement cannot compensate for a regression elsewhere.
Zero-denominator metrics use `defined: false` (no numeric bound); a previously
defined metric must remain defined. Corpora are never pooled.

To refresh after an improvement, run the old gate first, then:

```sh
GOPROXY=off GOTOOLCHAIN=local go test ./tests/eval \
  -run '^TestOfflineRegressionGate$' -count=1 -update-eval-baseline
```

The refresh refuses regressions against the old baseline. Review and commit the
old/new metrics and corrected case IDs as evidence; do not relax thresholds or
edit corpus labels to get a pass. See [ADR 0015](adr/0015-offline-regression-gate.md)
and the [evaluation CLI documentation](../cmd/guardrail-eval/README.md). Baseline refresh,
floors and the corpus are described in [`tests/eval/README.md`](../tests/eval/README.md) and
[ADR 0018](adr/0018-french-injection-recall.md).

## Semantic model bench (held-out French split)

`cmd/guardrail-bench` ([ADR 0023](adr/0023-semantic-model-bench.md),
[usage](../cmd/guardrail-bench/README.md)) compares semantic options through the real
service on the French benchmark of [ADR 0022](adr/0022-semantic-bench-corpus.md):
thresholds and the cascade gray zone are tuned on the calibration split only, frozen
in a committed protocol, then each candidate runs once on the 160-case test split.
It is a manual measurement (models in containers, a paid judge), not a CI gate; its
offline tests run with `go test ./cmd/guardrail-bench/...`.

Test split (80 attacks, 80 benign texts), chains as blocking policies:

| Configuration | Recall (95% CI) | FPR (95% CI) | p50 |
|---|---|---|---:|
| rules | 13/80 = 16.2% [9.7, 25.8] | 1/80 = 1.2% [0.2, 6.7] | 1 ms |
| rules + Prompt Guard 2 86M at 0.9 (reference) | 20/80 = 25.0% [16.8, 35.5] | 2/80 = 2.5% [0.7, 8.7] | 205 ms |
| rules + Qwen3Guard-Gen-0.6B | 31/80 = 38.8% [28.8, 49.7] | 2/80 = 2.5% [0.7, 8.7] | 2.9 s |
| rules + cascade (86M, judge in the gray zone) | 33/80 = 41.2% [31.1, 52.2] | 3/80 = 3.8% [1.3, 10.5] | 208 ms |
| rules + System One judge | 72/80 = 90.0% [81.5, 94.8] | 3/79 = 3.8% [1.3, 10.6], 1 error | 133 ms |

Recalibrated 86M, 22M, ProtectAI DeBERTa v2 and Qualifire Sentinel add nothing over
the reference at a calibrated threshold. The judge cost USD 0.019 per 1000 requests
(real paid traffic of the whole bench: 160 calls, USD 0.0031). The historical corpora
are measured again as diagnostics only. Full tables, latency, cost, licenses, limits
and the recommendation:
[`deploy/semantic-sidecar/EVALUATION.md`](../deploy/semantic-sidecar/EVALUATION.md).
