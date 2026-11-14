#!/usr/bin/env bash
# Semantic model bench driver (ADR 0023). Phases, in order:
#
#   build                      compile cmd/guardrail-bench
#   calibration                rules + every model on the calibration split (live sidecars)
#   freeze                     R1/R2 -> protocol.json (commit it before going on)
#   test                       every model on bench-test and the historical corpora (live),
#                              rules runs, Prompt Guard 2 86M at 0.9 replayed from the cache
#   judge                      System One alone on bench-test (paid; key on file descriptor 3)
#   cascade                    rules -> 86M -> judge in the gray zone, replayed (no new call)
#   report                     bundle + results JSON + Markdown + chart (no key, no model)
#
# Images are built beforehand (README.md "Bench"), one per model, tagged
# guardrail-bench-sidecar:<model>. One sidecar runs at a time, 2 CPUs, loopback port only.
# RUNNER=heavy prefixes every measured command on shared hosts.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
BENCH=$ROOT/deploy/semantic-sidecar/bench
RESULTS=$BENCH/results
OUT=${BENCH_OUT:-$ROOT/.agent-tmp/bench-runs}
CACHE=${BENCH_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/guardrail-bench}
BIN=${BENCH_BIN:-$ROOT/.agent-tmp/bin/guardrail-bench}
SUFFIX=${BENCH_SUFFIX:-$(basename "$ROOT")}
RUNNER=${RUNNER:-}
read -r -a MODELS <<< "${BENCH_MODELS:-pg2-86m pg2-22m deberta-v2 sentinel qwen3guard-0.6b}"
HISTORY=(french-injection-v1 original-v1)
export GOMAXPROCS=2

labels() {
  case $1 in
    pg2-86m|pg2-22m) echo LABEL_1 ;; deberta-v2) echo INJECTION ;;
    sentinel) echo jailbreak ;; qwen3guard-0.6b) echo Jailbreak ;;
  esac
}

bench() { $RUNNER nice "$BIN" "$@"; }

sidecar_up() { # model -> prints base URL
  local model=$1 name="guardrail-bench-$1-$SUFFIX" image="guardrail-bench-sidecar:$1"
  local args=(-d --name "$name" --label io.guardrail-serve.bench=l12 -p 127.0.0.1::8080
    --read-only --tmpfs /tmp:size=64m,mode=1777 --cap-drop ALL --security-opt no-new-privileges:true
    --pids-limit 128 --cpus 2 --memory 4g
    -e SIDECAR_MALICIOUS_LABELS="$(labels "$model")" -e SIDECAR_TORCH_THREADS=2 -e SIDECAR_BATCH_SIZE=8
    -e SIDECAR_INFERENCE_TIMEOUT_SECONDS=60 -e SIDECAR_REQUEST_TIMEOUT_SECONDS=90)
  if [ "$model" = sentinel ]; then
    # ModernBERT reaches torch inductor, which needs a user name for the non-root uid.
    args+=(-e USER=sidecar -e TORCHINDUCTOR_CACHE_DIR=/tmp/inductor)
  fi
  if [ "$model" = qwen3guard-0.6b ]; then
    # Prompt moderation wraps each text in the chat template: count the whole prompt.
    args+=(-e SIDECAR_MAX_TOKENS=2048 -v "$BENCH:/bench:ro" --entrypoint python "$image" /bench/qwen3guard.py serve)
  else
    args+=("$image")
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run "${args[@]}" >/dev/null
  local port
  port=$(docker port "$name" 8080/tcp | head -1 | sed 's/.*://')
  for _ in $(seq 1 180); do
    if curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; then
      echo "http://127.0.0.1:$port"
      return 0
    fi
    sleep 1
  done
  docker logs --tail 20 "$name" >&2
  echo "sidecar $model did not become ready" >&2
  return 1
}

sidecar_down() { docker rm -f "guardrail-bench-$1-$SUFFIX" >/dev/null 2>&1 || true; }

image_id() { docker image inspect --format '{{.Id}}' "guardrail-bench-sidecar:$1"; }

run_live() { # model corpus threshold-source run-id
  local model=$1 corpus=$2 source=$3 id=$4 url=$5 protocol=()
  [ "$corpus" = bench-calibration ] || protocol=(-protocol "$RESULTS/protocol.json")
  bench run -root "$ROOT" -mode union -model "$model" -corpus "$corpus" -threshold "$source" "${protocol[@]}" \
    -sidecar-url "$url" -sidecar-image "$(image_id "$model")" -cache-dir "$CACHE" \
    -run-id "$id" -out "$OUT/$id.json" -log "$OUT/$id.log"
}

phase=${1:-}
mkdir -p "$OUT" "$RESULTS"
case $phase in
  build)
    cd "$ROOT" && $RUNNER go build -o "$BIN" ./cmd/guardrail-bench ;;
  calibration)
    [ -e "$OUT/calibration-rules.json" ] || bench run -root "$ROOT" -mode rules -corpus bench-calibration -cache-dir "$CACHE" \
      -run-id calibration-rules -out "$OUT/calibration-rules.json"
    for model in "${MODELS[@]}"; do
      [ ! -e "$OUT/calibration-$model.json" ] || continue
      url=$(sidecar_up "$model")
      run_live "$model" bench-calibration frozen "calibration-$model" "$url" || { sidecar_down "$model"; exit 1; }
      sidecar_down "$model"
    done ;;
  freeze)
    if [ -e "$RESULTS/protocol.json" ]; then echo "protocol.json exists: the protocol is frozen" >&2; exit 1; fi
    bench calibrate -rules "$OUT/calibration-rules.json" -out "$RESULTS/protocol.json" \
      $(for model in "${MODELS[@]}"; do echo "$OUT/calibration-$model.json"; done) ;;
  test)
    git -C "$ROOT" ls-files --error-unmatch "$RESULTS/protocol.json" >/dev/null || { echo "commit protocol.json first" >&2; exit 1; }
    for corpus in bench-test "${HISTORY[@]}"; do
      bench run -root "$ROOT" -mode rules -corpus "$corpus" -protocol "$RESULTS/protocol.json" -cache-dir "$CACHE" \
        -run-id "$corpus-rules" -out "$OUT/$corpus-rules.json"
    done
    for model in "${MODELS[@]}"; do
      url=$(sidecar_up "$model")
      for corpus in bench-test "${HISTORY[@]}"; do
        run_live "$model" "$corpus" frozen "$corpus-$model-frozen" "$url" || { sidecar_down "$model"; exit 1; }
      done
      sidecar_down "$model"
    done
    for corpus in bench-test "${HISTORY[@]}"; do
      bench run -root "$ROOT" -mode union -model pg2-86m -corpus "$corpus" -threshold current -replay-delay \
        -protocol "$RESULTS/protocol.json" -cache-dir "$CACHE" -run-id "$corpus-pg2-86m-current" -out "$OUT/$corpus-pg2-86m-current.json"
    done ;;
  judge)
    # The key arrives on file descriptor 3 (never an argument, never the environment), read
    # once. The proxy stops paid traffic if the API serves another version than jev-1.14.0;
    # check the name beforehand with `guardrail-bench jev-probe` (one capped call).
    bench run -root "$ROOT" -mode judge -corpus bench-test -protocol "$RESULTS/protocol.json" -cache-dir "$CACHE" \
      -jev-live -jev-key-file /dev/fd/3 -run-id bench-test-jev -out "$OUT/bench-test-jev.json" -log "$OUT/bench-test-jev.log" ;;
  cascade)
    bench run -root "$ROOT" -mode cascade -model pg2-86m -corpus bench-test -replay-delay -protocol "$RESULTS/protocol.json" \
      -cache-dir "$CACHE" -run-id bench-test-cascade-replay -out "$OUT/bench-test-cascade-replay.json" -log "$OUT/bench-test-cascade-replay.log"
    bench run -root "$ROOT" -mode cascade -model pg2-86m -corpus bench-test -protocol "$RESULTS/protocol.json" \
      -cache-dir "$CACHE" -run-id bench-test-cascade-warm -out "$OUT/bench-test-cascade-warm.json" ;;
  report)
    "$BIN" export -protocol "$RESULTS/protocol.json" -out "$RESULTS/runs.json" "$OUT"/*.json
    "$BENCH/reproduce-report.sh" ;;
  *)
    sed -n '2,15p' "$0" >&2
    exit 2 ;;
esac
