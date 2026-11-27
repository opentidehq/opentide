#!/usr/bin/env bash
# Names: opentide, never otide. No opentide-sql crate/package.
# Documentation that forbids those names, and the throwing createOtideClient
# stub, are allowed.
#
# The crates' sources state their own contracts: never "the oracle's ..." or
# "the oracle does ..." in any case (the retired Python CLI is not the spec,
# and "oracle" is kept for the vendor parsers) and never a `.py` file that is not in this tree (#1958). A crate
# the sweep has not reached yet is held to its count in RETIRED_BASELINE,
# which only goes down.
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
# opentidehq/specifications' reference checker for the Exabeam Query Language.
external_py=" scripts/exabeam_language.py "
# Lines that name a vendor parser's oracle (Kusto's, in opentide-kql), not
# the retired Python CLI.
VENDOR_ORACLE="as the oracle probes|The oracle the lazy catalog is held to"
# Mentions of the retired Python CLI each crate still has, until it is swept.
declare -A RETIRED_BASELINE=(
  [opentide-cli]=172
  [opentide-compile]=121
  [opentide-schema]=238
)
tracked_py="$(git -C "$root" ls-files '*.py')"
py_in_tree() {
  local name="$1" path
  [[ "$external_py" == *" $name "* ]] && return 0
  while IFS= read -r path; do
    [[ "$path" == "$name" || "$path" == */"$name" ]] && return 0
  done <<<"$tracked_py"
  return 1
}
retired_mentions() {
  local dir="$1" hit
  # Any case: "the oracle's ...", "oracles' ...", "the Python oracle", and
  # "the oracle" with a verb or anything else after it ("the oracle did",
  # "the oracle (0.23) does", `in_the_oracles_order`). The vendor-parser
  # oracles are named by their own words: their recordings under
  # `oracles/`, and the two KQL comments in VENDOR_ORACLE.
  { grep -RInE -i "oracle's|oracles'|python oracle|(^|[^a-z])the[ _]oracles?([^a-z/]|\$)" "$dir" || true; } \
    | grep -vE "$VENDOR_ORACLE" || true
  { grep -RInoE '[A-Za-z0-9_./-]+\.py\b' "$dir" || true; } | while IFS= read -r hit; do
    py_in_tree "${hit##*:}" || echo "$hit"
  done
}
failed=0
for dir in "$root"/crates/*/src; do
  crate="$(basename "$(dirname "$dir")")"
  mentions="$(retired_mentions "$dir" | sed "s|^$root/||")"
  count=0
  if [[ -n "$mentions" ]]; then
    count="$(wc -l <<<"$mentions")"
  fi
  allowed="${RETIRED_BASELINE[$crate]:-0}"
  if ((count > allowed)); then
    echo "$mentions"
    echo "$crate: $count mentions of the retired Python CLI (\"the oracle\" in any form, or a .py file not in the tree), $allowed allowed."
    echo "  Say what the code does and the contract it keeps instead (#1958)."
    failed=1
  elif ((count < allowed)); then
    echo "$crate: $count mentions of the retired Python CLI; lower RETIRED_BASELINE[$crate] from $allowed to $count in scripts/engine/check-names.sh."
    failed=1
  fi
done
if ((failed)); then
  exit 1
fi
echo "names ok"
