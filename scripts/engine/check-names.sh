#!/usr/bin/env bash
# Names: opentide, never otide. No opentide-sql crate/package.
# Documentation that forbids those names, and the throwing createOtideClient
# stub, are allowed.
#
# The crates' sources, tests, guides and manifests, and xtask, state their own
# contracts: never "the oracle's ..." or
# "the oracle does ..." in any case (the retired Python CLI is not the spec,
# and "oracle" is kept for the vendor parsers) and never a `.py` file that is
# not in this tree (#1958). Any mention fails.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
hits="$(
  grep -RIn --exclude-dir=target --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=dist \
    -E 'createOtideClient\(|opentide-sql' "$root" \
    | grep -v 'check-names' \
    | grep -vE 'not a valid|never use|never |There is no|out of scope|@deprecated|is rejected' \
    | grep -v 'export function createOtideClient' \
    | grep -v 'index.test.ts' \
    || true
)"
if [[ -n "$hits" ]]; then
  echo "$hits"
  echo "forbidden identifier found"
  exit 1
fi

# Python files of other repositories that the sources cite on purpose:
# opentidehq/specifications' reference checker for the Exabeam Query Language,
# and its tests, whose block-code cases opentide-schema runs.
external_py=" scripts/exabeam_language.py test_platform_exabeam.py "
# Lines that name a vendor parser's oracle (Kusto's, in opentide-kql), not
# the retired Python CLI.
VENDOR_ORACLE="as the oracle probes|The oracle the lazy catalog is held to"
tracked_py="$(git -C "$root" ls-files '*.py')"
py_in_tree() {
  local name="$1" path
  [[ "$external_py" == *" $name "* ]] && return 0
  while IFS= read -r path; do
    [[ "$path" == "$name" || "$path" == */"$name" ]] && return 0
  done <<<"$tracked_py"
  return 1
}
# Paths of the live Python baseline (see scan_paths).
LIVE_BASELINE="^xtask/(src/(bench|corpus)/|tests/(cmd/(bench|corpus|usage)|bench\\.rs|corpus_)|AGENTS\\.md)"
retired_mentions() {
  local dir="$1" hit
  # Any case: "the oracle's ...", "oracles' ...", "the Python oracle", and
  # "the oracle" with a verb or anything else after it ("the oracle did",
  # "the oracle (0.23) does", `in_the_oracles_order`). The vendor-parser
  # oracles are named by their own words: their recordings under
  # `oracles/`, and the two KQL comments in VENDOR_ORACLE.
  { grep -RHInE -i --exclude-dir=target --exclude-dir=oracles "oracle's|oracles'|python oracle|(^|[^a-z])the[ _]oracles?([^a-z/]|\$)" "$dir" || true; } \
    | grep -vE "$VENDOR_ORACLE" || true
  # A name followed by `(` is a call (pyo3's `value.py()`), not a file.
  { grep -RHInoE --exclude-dir=target --exclude-dir=oracles '[A-Za-z0-9_./-]+\.py\b\(?' "$dir" || true; } | while IFS= read -r hit; do
    [[ "$hit" == *"(" ]] && continue
    py_in_tree "${hit##*:}" || echo "$hit"
  done
}
# Where the scan reads: each crate's sources, tests, guide and manifest, the
# crates' own guide, and xtask. Left out: the vendor parsers' recordings and
# fixtures (`oracles/` folders), and the tools that still run a pinned release
# of the Python CLI as a baseline (the benchmarks' `--engine python` and the
# fault corpus's reference run: `xtask/src/bench`, `xtask/src/corpus`, their
# tests and xtask's guide), which name that baseline "the oracle" because it is
# one.
scan_paths=()
for crate in "$root"/crates/*/; do
  crate="${crate%/}"
  for path in "$crate/src" "$crate/tests" "$crate/AGENTS.md" "$crate/Cargo.toml"; do
    [[ -e "$path" ]] && scan_paths+=("$path")
  done
done
scan_paths+=("$root/crates/AGENTS.md" "$root/xtask")
failed=0
for dir in "${scan_paths[@]}"; do
  mentions="$(retired_mentions "$dir" | sed "s|^$root/||" | grep -vE "$LIVE_BASELINE" || true)"
  if [[ -n "$mentions" ]]; then
    echo "$mentions"
    echo "${dir#"$root"/}: mentions of the retired Python CLI (\"the oracle\" in any form, or a .py file not in the tree)."
    echo "  Say what the code does and the contract it keeps instead (#1958)."
    failed=1
  fi
done
if ((failed)); then
  exit 1
fi
echo "names ok"
