#!/usr/bin/env bash
# Rebuild the bench results, tables and chart from the committed, text-free run
# bundle and protocol. Needs Go and uv; no model, no key, no network beyond uv's
# one-time download of the pinned matplotlib.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
RESULTS=$ROOT/deploy/semantic-sidecar/bench/results
cd "$ROOT"
go run ./cmd/guardrail-bench report -root "$ROOT" -bundle "$RESULTS/runs.json.gz" -protocol "$RESULTS/protocol.json" \
  -out "$RESULTS/results.json" -markdown "$RESULTS/results.md"
uv run --no-project --python 3.13 --with matplotlib==3.10.7 \
  python -I "$ROOT/deploy/semantic-sidecar/bench/plot_bench.py" "$RESULTS/results.json" "$RESULTS/bench-test.png"
