#!/usr/bin/env bash
# Names: opentide, never otide. No opentide-sql crate/package.
# Documentation that forbids those names, and the throwing createOtideClient
# stub, are allowed.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
hits="$(
  grep -RIn --exclude-dir=target --exclude-dir=.git --exclude-dir=node_modules \
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
echo "names ok"
