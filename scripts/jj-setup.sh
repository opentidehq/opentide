#!/usr/bin/env bash
# Bootstrap Jujutsu for OpenTide. Optionally remove Graphite.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=jj-common.sh
source "$(dirname "${BASH_SOURCE[0]}")/jj-common.sh"

REMOVE_GRAPHITE=0
for arg in "$@"; do
  [[ "$arg" == "--remove-graphite" ]] && REMOVE_GRAPHITE=1
done

echo "==> Installing Jujutsu (jj)"
if command -v jj >/dev/null 2>&1; then
  echo "jj already installed: $(jj --version)"
else
  if command -v brew >/dev/null 2>&1; then
    brew install jj
  else
    echo "Install jj manually: https://github.com/jj-vcs/jj" >&2
    exit 1
  fi
fi

if [[ "$REMOVE_GRAPHITE" == 1 ]]; then
  echo "==> Removing Graphite (gt)"
  if command -v brew >/dev/null 2>&1 && brew list withgraphite/tap/graphite &>/dev/null; then
    brew uninstall withgraphite/tap/graphite || true
  fi
  rm -rf "${HOME}/.config/graphite"
  rm -rf "${HOME}/.graphite"
  if command -v gt >/dev/null 2>&1; then
    echo "Warning: gt still on PATH at $(command -v gt)" >&2
  else
    echo "Graphite CLI removed."
  fi
fi

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "Not a git repository — run from an OpenTide clone or worktree" >&2
  exit 1
fi

echo "==> Configuring jj (user)"
jj config set --user ui.pager auto 2>/dev/null || true
jj config set --user git.auto-local-bookmark main 2>/dev/null || true
if ! jj config get user.email &>/dev/null; then
  echo "Warning: set jj identity before push (required for jj git push):"
  echo "  jj config set --user user.name \"Your Name\""
  echo "  jj config set --user user.email \"you@example.com\""
fi

GIT_DIR="$(git rev-parse --git-dir)"
GIT_COMMON="$(git rev-parse --git-common-dir)"
if [[ "$GIT_COMMON" != /* ]]; then
  GIT_COMMON="$(cd "$(dirname "$GIT_COMMON")" && pwd)/$(basename "$GIT_COMMON")"
fi
MAIN_ROOT="$(dirname "$GIT_COMMON")"
IS_WORKTREE=0
if [[ "$GIT_DIR" != "$GIT_COMMON" ]]; then
  IS_WORKTREE=1
fi

_ensure_colocated_in() {
  local target="$1"
  echo "==> Colocated jj at ${target}"
  if [[ -d "${target}/.jj" ]]; then
    echo ".jj already present"
    return 0
  fi
  (cd "$target" && jj git init --colocate)
  echo "Initialized colocated jj in ${target}"
}

if [[ "$IS_WORKTREE" == 1 ]]; then
  echo "Secondary checkout detected ($(pwd))"
  if [[ -d "${ROOT}/.jj" ]]; then
    echo ".jj already present"
  else
    echo "==> jj git backend (jj git init --git-repo=.)"
    echo "    Prefer a single clone on development when possible."
    jj git init --git-repo=.
  fi
else
  _ensure_colocated_in "$ROOT"
fi

JJ_REPO="$(jj_repo_root)"
jj_cmd bookmark track development --remote=origin 2>/dev/null || true
echo "Fetch remote bookmarks:"
jj_cmd git fetch 2>/dev/null || echo "(fetch skipped — configure origin if needed)"

echo
echo "==> jj repo: ${JJ_REPO}"
echo "==> Next steps"
echo "  1. scripts/jj-submit.sh <bookmark>       # single PR"
echo "  2. scripts/jj-stack-status.sh            # view stack"
echo "  3. scripts/jj-stack-submit.sh --dry-run <bookmark>"
echo "  4. Read AGENTS.md § Jujutsu"
echo "  5. uv run pre-commit install --install-hooks"
