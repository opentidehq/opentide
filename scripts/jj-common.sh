#!/usr/bin/env bash
# Shared jj helpers for OpenTide scripts.
set -euo pipefail

# Resolve jj repo root: prefer .jj in the current checkout (incl. git worktrees).
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

# Run jj in the current checkout when it has .jj; else fall back to primary -R.
jj_cmd() {
  if jj root >/dev/null 2>&1; then
    command jj "$@"
    return
  fi
  local root
  root="$(jj_repo_root)" || {
    echo "No jj repo found. Run: scripts/jj-setup.sh" >&2
    return 1
  }
  command jj -R "$root" "$@"
}
