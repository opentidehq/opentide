#!/usr/bin/env bash
# The language server's cold start (#1754): spawn to the first diagnostics of a rule it was asked
# to open, native and WASI, on the small and the large workspace, measured by the scripted client
# (scripts/perf/lsp-bench.mjs) and written as one report per scenario, which
# scripts/perf/check_cold_start.py holds to tests/bench/lsp-cold-start.toml.
#
#   scripts/perf/cold-start.sh OUT NATIVE_SERVER WASI_MODULE
#
# NATIVE_SERVER: opentide-lsp built --release; WASI_MODULE: opentide-lsp.wasm built --release for
# wasm32-wasip1, run under wasmtime, the host the budgets were measured with (`wasmtime` on PATH).
# WASI_HOST=node runs it under Node's WASI instead (scripts/engine/wasi-run.mjs), for comparing two
# builds on one machine: Node's own start and its compile of the module add about 100 ms, so those
# numbers are not the budgets'. RUNS (default 10) must match the budgets file's `runs`. Each run is
# a fresh server; nothing reaches the network.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:?OUT: where the reports go}"
NATIVE="${2:?NATIVE_SERVER: the opentide-lsp binary}"
WASI="${3:?WASI_MODULE: the opentide-lsp.wasm module}"
RUNS="${RUNS:-10}"
[ -x "$NATIVE" ] || { echo "cold-start.sh: $NATIVE is not an executable" >&2; exit 2; }
[ -f "$WASI" ] || { echo "cold-start.sh: no $WASI" >&2; exit 2; }
mkdir -p "$OUT"
# The client starts the server in the workspace: the paths must not be relative to here.
NATIVE="$(realpath "$NATIVE")"
WASI="$(realpath "$WASI")"
WASI_HOST="${WASI_HOST:-wasmtime}"
case "$WASI_HOST" in
  wasmtime) command -v wasmtime >/dev/null || { echo "cold-start.sh: no wasmtime on PATH (WASI_HOST=node runs Node's WASI)" >&2; exit 2; }
            wasmtime --version >&2 ;;
  node) ;;
  *) echo "cold-start.sh: WASI_HOST is wasmtime or node, not $WASI_HOST" >&2; exit 2 ;;
esac
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The workspaces of the measurements the budgets come from (docs/internal/datasets.md): the Tide
# corpus as it is, and the corpus's rules copied up to 1,000 object files.
python3 "$HERE/make_workspace.py" "$WORK/ws-small" --objects 0 >&2
python3 "$HERE/make_workspace.py" "$WORK/ws-large" --objects 1000 >&2

bench() { # id workspace command...
  local id="$1" ws="$2"; shift 2
  echo ">>> $id" >&2
  # --warm 1: the cold start is measured before any request the warm count repeats.
  node "$HERE/lsp-bench.mjs" --label "$id" --workspace "$ws" --runs "$RUNS" --warm 1 \
    --out "$OUT/$id.json" -- "$@" >&2
}

for size in small large; do
  bench "native_$size" "$WORK/ws-$size" "$NATIVE" --stdio
  if [ "$WASI_HOST" = wasmtime ]; then
    # The host's root is the guest's (the workspace's absolute paths), the environment passed in
    # whole, as wasi-run.mjs does.
    bench "wasi_$size" "$WORK/ws-$size" wasmtime run --dir / -S inherit-env "$WASI" --stdio
  else
    # --no-turbo-fast-api-calls: Node 22's fast WASI calls can start a garbage collection inside a
    # call, which crashes once the instance holds enough memory (wasi-run.mjs).
    bench "wasi_$size" "$WORK/ws-$size" node --no-turbo-fast-api-calls \
      "$HERE/../engine/wasi-run.mjs" "$WASI" --stdio
  fi
done
