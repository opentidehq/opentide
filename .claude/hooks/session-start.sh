#!/usr/bin/env bash
# SessionStart hook for Claude Code cloud sessions: sync the locked dev
# environment before the agent starts, so `uv run pytest`, ruff, ty and
# scripts/ci-local.sh work on the first call instead of each paying for (or
# racing) the install. Local sessions manage their own environment.
set -euo pipefail

if [[ "${CLAUDE_CODE_REMOTE:-}" != "true" ]]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
  export PATH="$HOME/.local/bin:$PATH"
  if [[ -n "${CLAUDE_ENV_FILE:-}" ]]; then
    echo "export PATH=\"$HOME/.local/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
  fi
fi

# `uv sync` builds the analysis engine (analysis/, Rust) with maturin, so the
# session needs cargo. rustup installs a minimal stable toolchain once.
if ! command -v cargo >/dev/null 2>&1; then
  if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
  else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --component rustfmt,clippy >/dev/null
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
  if [[ -n "${CLAUDE_ENV_FILE:-}" ]]; then
    echo "export PATH=\"$HOME/.cargo/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
  fi
fi

# Idempotent; the container caches the result after the first session.
uv sync --group dev --quiet

# The pre-commit hooks are deliberately not installed here: the pre-push hook
# runs scripts/ci-local.sh --full (~10 min). Agents run the checks themselves;
# see AGENTS.md "Definition of done".
