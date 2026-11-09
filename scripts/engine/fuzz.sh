#!/usr/bin/env bash
# Run one fuzz target with its seed corpora (fuzz/README.md, #182).
#   scripts/engine/fuzz.sh <target> [seconds]     default 300
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
target="${1:?target: kql spl esql eql kuery lucene falco cql tide protocol framing config cli}"
seconds="${2:-300}"
seeds=()
case "$target" in
  kql|spl|esql|eql|kuery|lucene|falco|cql)
    seeds+=("$root/crates/testdata/corpus/$target")
    [[ -d "$root/crates/testdata/conformance/external/$target" ]] && seeds+=("$root/crates/testdata/conformance/external/$target") ;;
  tide) seeds+=("$root/crates/testdata/objects" "$root/crates/testdata/workspaces/tide_corpus/objects") ;;
  protocol) seeds+=("$root/fuzz/seeds/protocol") ;;
  framing) seeds+=("$root/fuzz/seeds/framing") ;;
  config) seeds+=("$root/fuzz/seeds/config") ;;
  cli) seeds+=("$root/fuzz/seeds/cli") ;;
  *) echo "unknown target: $target" >&2; exit 2 ;;
esac
[[ -d "$root/fuzz/regressions/$target" ]] && seeds+=("$root/fuzz/regressions/$target")
mkdir -p "$root/fuzz/corpus/$target"
cd "$root"
# The dated nightly fuzz/NIGHTLY pins (CI's fuzz jobs install it); FUZZ_TOOLCHAIN overrides.
toolchain="${FUZZ_TOOLCHAIN:-$(cat "$root/fuzz/NIGHTLY")}"
exec cargo "+${toolchain}" fuzz run "$target" "fuzz/corpus/$target" "${seeds[@]}" -- \
  -timeout=10 -rss_limit_mb=4096 -max_total_time="$seconds"
