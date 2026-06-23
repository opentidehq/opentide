#!/usr/bin/env bash
# Show the current jj bookmark stack from trunk (development@origin) to @.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=jj-common.sh
source "$(dirname "${BASH_SOURCE[0]}")/jj-common.sh"

if ! command -v jj >/dev/null 2>&1; then
  echo "jj not found. Run: scripts/jj-setup.sh" >&2
  exit 1
fi

TRUNK="${JJ_TRUNK:-development@origin}"

echo "==> Stack from ${TRUNK} to @"
echo

jj_cmd log -r "${TRUNK}..@" --reversed --no-graph \
  -T 'if(local_bookmarks, local_bookmarks.join(",") ++ " ", "") ++ description.first_line() ++ "\n"'

echo
echo "Bookmarks:"
jj_cmd bookmark list 2>/dev/null | rg -v '@origin' || jj_cmd bookmark list
