# guardrail-bench

Semantic model bench ([ADR 0023](../../docs/adr/0023-semantic-model-bench.md)). It runs
the real guardrail-serve handler in-process on loopback, sends every case of one corpus
once (concurrency 1), records classifier scores and System One answers through caching
proxies, freezes thresholds and the gray zone from the calibration split, and reports
per-configuration metrics from text-free run files. Results and their interpretation:
[`deploy/semantic-sidecar/EVALUATION.md`](../../deploy/semantic-sidecar/EVALUATION.md)
and [`docs/evaluation.md`](../../docs/evaluation.md).

## Commands

```text
guardrail-bench run        -corpus C -mode rules|union|judge|cascade [-model M] ...
guardrail-bench calibrate  -rules R -out protocol.json <one classifier run per model>
guardrail-bench export     -protocol P -out runs.json <run files>
guardrail-bench report     -bundle runs.json -protocol P -out results.json [-markdown results.md]
guardrail-bench jev-models -jev-key-file /dev/fd/3
```

- Corpora: `bench-calibration`, `bench-test` (ADR 0022, hashes checked against the
  manifest), `french-injection-v1`, `original-v1` (historical, reported apart).
- Models (pinned revision and weights sha256 in `bench/models.go`): `pg2-86m`,
  `pg2-22m`, `deberta-v2`, `sentinel`, `qwen3guard-0.6b`.
- `union` with `-sidecar-url` records live scores; without it, it replays the cache
  (`-replay-delay` sleeps the recorded upstream latency). Test runs take their
  threshold from the protocol (`-threshold frozen`, or `current` = 0.9 for `pg2-86m`).
- `judge` runs on `bench-test` only. `-jev-live` allows paid calls, capped by
  `-max-calls` (200) and `-max-usd` (1); the key is read from `-jev-key-file`, for
  example `/dev/fd/3`, never from an argument or the environment. Without `-jev-live`
  the proxy is cache-only.
- `cascade` replays both caches: no inference and no paid call.

Errors (non-200 answers of the service, including fail-closed judge or classifier
failures and egress-guard refusals) are counted apart and never as detections.

## Driver

[`deploy/semantic-sidecar/bench/run-bench.sh`](../../deploy/semantic-sidecar/bench/run-bench.sh)
runs the phases in order (`build`, `calibration`, `freeze`, `test`, `judge`,
`cascade`, `report`) with one sidecar container at a time (2 CPUs, 4 GB, loopback port,
read-only). `reproduce-report.sh` rebuilds results, tables and the chart from the
committed bundle without a model or a key.

## Tests

`go test ./cmd/guardrail-bench/...` is offline: metrics, R1/R2 calibration, protocol
enforcement, proxy cache and replay, budget stops, egress guard, the report and its
consistency checks, and a wire test that runs the whole `bench-test` split through the
real masking into a fake System One and checks that no raw synthetic secret or personal
value leaves the host.
