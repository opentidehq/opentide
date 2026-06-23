#!/usr/bin/env bash
# Push a single jj bookmark to GitHub and create/update one PR (base: trunk).
#
# Usage: scripts/jj-submit.sh [bookmark] [--draft] [--dry-run]
#
# For stacked PRs use scripts/jj-stack-submit.sh instead.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=jj-common.sh
source "$(dirname "${BASH_SOURCE[0]}")/jj-common.sh"

TRUNK="${JJ_TRUNK:-development}"
DRAFT=0
DRY_RUN=0
BOOKMARK=""

for arg in "$@"; do
  case "$arg" in
    --draft) DRAFT=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,7p' "$0"
      exit 0
      ;;
    *) BOOKMARK="$arg" ;;
  esac
done

if ! command -v jj >/dev/null 2>&1; then
  echo "jj not found. Run: scripts/jj-setup.sh" >&2
  exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "gh not found. Install GitHub CLI." >&2
  exit 1
fi

if [[ -z "$BOOKMARK" ]]; then
  mapfile -t ON_HEAD < <(jj_cmd log -r @ -T 'local_bookmarks' --no-graph | tr -d ' ')
  if [[ ${#ON_HEAD[@]} -eq 0 || -z "${ON_HEAD[0]}" ]]; then
    echo "No bookmark on @. Create one: jj bookmark create feat/slug" >&2
    exit 1
  fi
  BOOKMARK="${ON_HEAD[0]}"
fi

echo "==> Submit bookmark: ${BOOKMARK} (base: ${TRUNK})"

if [[ "$DRY_RUN" == 1 ]]; then
  echo "  jj git push --bookmark ${BOOKMARK}"
  echo "  gh pr create --base ${TRUNK} --head ${BOOKMARK} ..."
  exit 0
fi

jj_cmd git push --bookmark "$BOOKMARK"
EXISTING=$(gh pr list --head "$BOOKMARK" --base "$TRUNK" --state open --json number -q '.[0].number' 2>/dev/null || true)
if [[ -n "$EXISTING" && "$EXISTING" != "null" ]]; then
  echo "PR already open: #${EXISTING}"
  gh pr view "$EXISTING" --web 2>/dev/null || true
  exit 0
fi

TITLE=$(jj_cmd log -r "$BOOKMARK" -T 'description.first_line()' --no-graph | head -1)
BODY="## Summary
${TITLE}

## Test plan
- [ ] \`scripts/ci-local.sh --full\`
"
CREATE_ARGS=(pr create --base "$TRUNK" --head "$BOOKMARK" --title "$TITLE" --body "$BODY")
if [[ "$DRAFT" == 1 ]]; then
  CREATE_ARGS+=(--draft)
fi
gh "${CREATE_ARGS[@]}"
echo "==> Done."
