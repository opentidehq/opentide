#!/usr/bin/env bash
# The editor-latency matrix: every runtime tier on the small and the large workspace, the same
# scripted client for each (scripts/perf/lsp-bench.mjs), raw samples kept as JSON under $OUT.
#
#   OUT=docs/internal/perf/data WORK=/path/with/artifacts scripts/perf/run-matrix.sh [tier ...]
#
# $WORK holds what each tier runs (see the table below); a tier whose file is missing is skipped.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:?OUT: where the JSON goes}"
WORK="${WORK:?WORK: where the artifacts are}"
RUNS="${RUNS:-10}"
WARM="${WARM:-20}"
PAUSE="${PAUSE:-100}"
mkdir -p "$OUT"
WASI_RUN="$HERE/../engine/wasi-run.mjs"

bench() { # label workspace-name workspace-dir extra-args... -- command...
  local label="$1" wsname="$2" ws="$3"; shift 3
  echo ">>> $label on $wsname" >&2
  node "$HERE/lsp-bench.mjs" --label "$label-$wsname" --workspace "$ws" --runs "$RUNS" --warm "$WARM" \
    --pause "$PAUSE" --out "$OUT/$label-$wsname.json" "$@" | sed -n 1,3p >&2
}

tiers=("$@")
[ ${#tiers[@]} -eq 0 ] && tiers=(py0.28.1 engine0.10.0 native-rc2 py1.0.0rc2 wasi-rc2 engine-rc2 wasi-fixed native-head native-fix-a native-fixed)

for tier in "${tiers[@]}"; do
  for wsname in small large; do
    ws="$WORK/ws-$wsname"
    case "$tier" in
      py0.28.1)    [ -x "$WORK/venv-028/bin/opentide" ] && bench "$tier" "$wsname" "$ws" -- "$WORK/venv-028/bin/opentide" lsp start ;;
      engine0.10.0) [ -f "$WORK/dl-engine/x/opentide_wasm.js" ] && bench "$tier" "$wsname" "$ws" --worker "$HERE/engine-worker.mjs" --module "$WORK/dl-engine/x/opentide_wasm_bg.wasm" --glue "$WORK/dl-engine/x/opentide_wasm.js" ;;
      native-rc2)  bin="$WORK/dl-rc2/opentide-lsp-v1.0.0-rc.2-x86_64-unknown-linux-gnu"; [ -x "$bin" ] && bench "$tier" "$wsname" "$ws" -- "$bin" --stdio ;;
      py1.0.0rc2)  [ -x "$WORK/venv-rc2/bin/opentide" ] && bench "$tier" "$wsname" "$ws" -- "$WORK/venv-rc2/bin/opentide" lsp start ;;
      wasi-rc2)    [ -f "$WORK/dl-rc2/opentide-lsp-wasm32-wasip1.wasm" ] && bench "$tier" "$wsname" "$ws" -- node --no-turbo-fast-api-calls "$WASI_RUN" "$WORK/dl-rc2/opentide-lsp-wasm32-wasip1.wasm" --stdio ;;
      wasi-fixed)  [ -f "$WORK/bins/opentide-lsp-fixed.wasm" ] && bench "$tier" "$wsname" "$ws" -- node --no-turbo-fast-api-calls "$WASI_RUN" "$WORK/bins/opentide-lsp-fixed.wasm" --stdio ;;
      engine-rc2)  [ -f "$WORK/dl-rc2/web/opentide_wasm.js" ] && bench "$tier" "$wsname" "$ws" --worker "$HERE/engine-worker.mjs" --module "$WORK/dl-rc2/web/opentide_wasm_bg.wasm" --glue "$WORK/dl-rc2/web/opentide_wasm.js" ;;
      native-head) [ -x "$WORK/bins/opentide-lsp-head" ] && bench "$tier" "$wsname" "$ws" -- "$WORK/bins/opentide-lsp-head" --stdio ;;
      native-fix-a) [ -x "$WORK/bins/opentide-lsp-fix-a" ] && bench "$tier" "$wsname" "$ws" -- "$WORK/bins/opentide-lsp-fix-a" --stdio ;;
      native-fixed) [ -x "$WORK/bins/opentide-lsp-fixed" ] && bench "$tier" "$wsname" "$ws" -- "$WORK/bins/opentide-lsp-fixed" --stdio ;;
      *) echo "unknown tier $tier" >&2; exit 2 ;;
    esac
  done
done
