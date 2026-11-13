#!/usr/bin/env bash
# Run from the repository root. Toolchain/modules must already be provisioned.
set -euo pipefail
mkdir -p .agent-tmp/eval
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
# The harness owns and closes a real HTTP server on an assigned loopback port.
# No service environment, external model, dataset loader or fixed port is used.
go test ./tests/eval/gate -count=1
go test ./tests/eval -run '^TestOfflineRegressionGate$' -count=1 \
  -eval-report-dir "$(pwd)/.agent-tmp/eval"
