#!/usr/bin/env bash
# Fail CI when legacy log() shim imports reappear in application code.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

matches=$(rg -n "from opentide\.core\.logging import.*\blog\b|from opentide\.core\.logging import log\b" \
  src/opentide \
  --glob '!**/core/logging/**' || true)

if [[ -n "$matches" ]]; then
  echo "Legacy log() imports found (use get_logger instead):" >&2
  echo "$matches" >&2
  exit 1
fi

legacy_calls=$(rg -n '\blog\("' src/opentide --glob '!**/core/logging/**' || true)
if [[ -n "$legacy_calls" ]]; then
  echo "Legacy log(\"CATEGORY\", ...) calls found:" >&2
  echo "$legacy_calls" >&2
  exit 1
fi

echo "No legacy log() usage detected."
