#!/usr/bin/env bash
# Run one fuzz target with its seed corpora (fuzz/README.md, #182).
#   scripts/fuzz.sh <target> [seconds]     default 300
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
target="${1:?target: kql spl esql eql kuery lucene falco cql yara tide protocol}"
seconds="${2:-300}"
seeds=()
case "$target" in
  kql|spl|esql|eql|kuery|lucene|falco|cql|yara)
    [[ -d "$root/testdata/corpus/$target" ]] && seeds+=("$root/testdata/corpus/$target")
    [[ -d "$root/testdata/conformance/external/$target" ]] && seeds+=("$root/testdata/conformance/external/$target") ;;
  tide) seeds+=("$root/testdata/objects" "$root/testdata/workspaces/tide_corpus/objects") ;;
  protocol) seeds+=("$root/fuzz/seeds/protocol") ;;
  *) echo "unknown target: $target" >&2; exit 2 ;;
esac
[[ -d "$root/fuzz/regressions/$target" ]] && seeds+=("$root/fuzz/regressions/$target")
mkdir -p "$root/fuzz/corpus/$target"
cd "$root"
exec cargo +nightly fuzz run "$target" "fuzz/corpus/$target" "${seeds[@]}" -- \
  -timeout=10 -rss_limit_mb=4096 -max_total_time="$seconds"
