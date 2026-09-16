#!/usr/bin/env bash
# Engine crates must stay I/O-free (library sources only; tests may touch the filesystem).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
fail=0
for crate in opentide-kql opentide-spl opentide-tide opentide-analysis opentide-core opentide-highlight opentide-syntax; do
  matches="$(grep -R --include='*.rs' -nE 'use std::fs|std::fs::' "$root/crates/$crate/src" 2>/dev/null || true)"
  if [[ -n "$matches" ]]; then
    echo "std::fs found in $crate/src:"
    echo "$matches"
    fail=1
  fi
done
exit "$fail"
