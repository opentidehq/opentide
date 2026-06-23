#!/usr/bin/env bash
# Shared jj helpers for OpenTide scripts (git worktree-safe).
set -euo pipefail

# Resolve the colocated jj repository root (primary checkout).
jj_repo_root() {
  if root="$(jj root 2>/dev/null)"; then
    printf '%s\n' "$root"
    return 0
  fi
  if ! git rev-parse --git-common-dir >/dev/null 2>&1; then
    return 1
  fi
  local common main_root
  common="$(git rev-parse --git-common-dir)"
  if [[ "$common" != /* ]]; then
    common="$(cd "$(dirname "$common")" && pwd)/$(basename "$common")"
  fi
  main_root="$(dirname "$common")"
  if [[ -d "${main_root}/.jj" ]]; then
    printf '%s\n' "$main_root"
    return 0
  fi
  return 1
}

# Run jj against the resolved repo (works from git worktrees).
jj_cmd() {
  local root
  root="$(jj_repo_root)" || {
    echo "No jj repo found. Run: scripts/jj-setup.sh" >&2
    return 1
  }
  command jj -R "$root" "$@"
}
