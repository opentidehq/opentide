#!/usr/bin/env bash
# Bootstrap Jujutsu for OpenTide stacked-PR workflow. Optionally remove Graphite.
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
  echo "Git worktree detected ($(pwd))"
  PRIMARY="$(git worktree list --porcelain | awk '/^worktree / { print $2; exit }')"
  if [[ -z "$PRIMARY" ]]; then
    PRIMARY="$MAIN_ROOT"
  fi
  _ensure_colocated_in "$PRIMARY"
  echo "jj commands from this worktree use: jj -R ${PRIMARY} (via scripts/jj-common.sh)"
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
echo "  1. scripts/jj-stack-status.sh          # view stack"
echo "  2. scripts/jj-stack-submit.sh --dry-run <bookmark>"
echo "  3. Read AGENTS.md § Jujutsu stacked PRs"
echo "  4. uv run pre-commit install --install-hooks"
