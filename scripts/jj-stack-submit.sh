#!/usr/bin/env bash
# Push a jj bookmark stack to GitHub and create/update stacked PRs (bottom → top).
#
# Usage: scripts/jj-stack-submit.sh [top-bookmark] [--draft] [--dry-run]
#
# Requires: jj, gh (authenticated), colocated jj repo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=jj-common.sh
source "$(dirname "${BASH_SOURCE[0]}")/jj-common.sh"

TRUNK="${JJ_TRUNK:-development}"
TRUNK_REMOTE="${JJ_TRUNK_REMOTE:-development@origin}"
DRAFT=0
DRY_RUN=0
TOP_BOOKMARK=""

for arg in "$@"; do
  case "$arg" in
    --draft) DRAFT=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,6p' "$0"
      exit 0
      ;;
    *) TOP_BOOKMARK="$arg" ;;
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

if [[ -z "$TOP_BOOKMARK" ]]; then
  # Use bookmarks on @
  mapfile -t ON_HEAD < <(jj_cmd log -r @ -T 'local_bookmarks' --no-graph | tr -d ' ')
  if [[ ${#ON_HEAD[@]} -eq 0 || -z "${ON_HEAD[0]}" ]]; then
    echo "No bookmark on @. Pass top bookmark: scripts/jj-stack-submit.sh <bookmark>" >&2
    exit 1
  fi
  TOP_BOOKMARK="${ON_HEAD[0]}"
fi

echo "==> Collecting stack for bookmark: ${TOP_BOOKMARK}"

# Bookmarks bottom → top (one per stacked change)
mapfile -t STACK_BOOKMARKS < <(
  jj_cmd log -r "${TRUNK_REMOTE}..${TOP_BOOKMARK}" --reversed --no-graph \
    -T 'local_bookmarks.first()' \
    | rg -v '^\s*$' || true
)

if [[ ${#STACK_BOOKMARKS[@]} -eq 0 ]]; then
  STACK_BOOKMARKS=("$TOP_BOOKMARK")
fi

echo "Stack (${#STACK_BOOKMARKS[@]}): ${STACK_BOOKMARKS[*]}"
echo

PREV_BASE="$TRUNK"
for bookmark in "${STACK_BOOKMARKS[@]}"; do
  echo "--- ${bookmark} (base: ${PREV_BASE}) ---"
  if [[ "$DRY_RUN" == 1 ]]; then
    echo "  jj git push --bookmark ${bookmark}"
    echo "  gh pr create --base ${PREV_BASE} --head ${bookmark} ..."
  else
    jj_cmd git push --bookmark "$bookmark"
    EXISTING=$(gh pr list --head "$bookmark" --base "$PREV_BASE" --state open --json number -q '.[0].number' 2>/dev/null || true)
    if [[ -n "$EXISTING" && "$EXISTING" != "null" ]]; then
      echo "  PR already exists: #${EXISTING}"
      gh pr edit "$EXISTING" --base "$PREV_BASE" 2>/dev/null || true
    else
      TITLE=$(jj_cmd log -r "$bookmark" -T 'description.first_line()' --no-graph | head -1)
      BODY="## Summary
${TITLE}

## Stack
Part of a jj stack. See the **Stack navigation** comment after CI runs.

## Test plan
- [ ] \`scripts/ci-local.sh --full\`
"
      CREATE_ARGS=(pr create --base "$PREV_BASE" --head "$bookmark" --title "$TITLE" --body "$BODY")
      if [[ "$DRAFT" == 1 ]]; then
        CREATE_ARGS+=(--draft)
      fi
      gh "${CREATE_ARGS[@]}"
    fi
  fi
  PREV_BASE="$bookmark"
  echo
done

echo "==> Done. Stack comment workflow will annotate PRs on GitHub."
