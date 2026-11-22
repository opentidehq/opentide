#!/usr/bin/env bash
# The in-editor rows: VS Code under Xvfb, the extension from $VSX (main = the released 0.1.2), each runtime
# through `opentide.path` (or none: the extension's WASM engine fallback). Raw JSON under $OUT.
#   OUT=... WORK=... CODE=.../VSCode-linux-x64/code VSX=/tmp/vsx scripts/perf/editor/run-matrix.sh [tier ...]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:?}"; WORK="${WORK:?}"; CODE="${CODE:?}"; VSX="${VSX:?}"; RUNS="${RUNS:-4}"; WARM="${WARM:-15}"
mkdir -p "$OUT"
one() { # label workspace server proc
  echo ">>> $1" >&2
  xvfb-run -a node "$HERE/run.mjs" --vsx "$VSX" --code "$CODE" --workspace "$WORK/ws-$2" --label "$1" --runs "$RUNS" \
    --warm "$WARM" --pause 100 ${3:+--server "$3"} ${4:+--proc "$4"} --out "$OUT/$1.json" 2>&1 | grep -E "runs|failed" >&2 || true
}
tiers=("$@"); [ ${#tiers[@]} -eq 0 ] && tiers=(py0.28.1 engine0.10.0 native-rc2 native-head native-fixed)
for t in "${tiers[@]}"; do
  case "$t" in
    py0.28.1)     one "ed-$t-large" large "$WORK/venv-028/bin/opentide" "venv-028/bin/opentide" ;;
    engine0.10.0) one "ed-$t-large" large "" "" ;;
    # The extension takes a runtime for a bare language server by its file name: `opentide-lsp`.
    native-rc2)   one "ed-$t-large" large "$WORK/bins/rc2/opentide-lsp" "bins/rc2/opentide-lsp" ;;
    native-head)  one "ed-$t-large" large "$WORK/bins/head/opentide-lsp" "bins/head/opentide-lsp" ;;
    native-fixed) one "ed-$t-large" large "$WORK/bins/fixed/opentide-lsp" "bins/fixed/opentide-lsp" ;;
    *) echo "unknown tier $t" >&2; exit 2 ;;
  esac
done
