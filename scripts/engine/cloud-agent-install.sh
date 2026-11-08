#!/usr/bin/env bash
# Cloud Agent environment bootstrap for the opentide language server.
# Idempotent: safe to run repeatedly and against a warm/cached checkout.
set -euo pipefail
cd "$(dirname "$0")/../.."

# ---------------------------------------------------------------------------
# tree-sitter CLI
# scripts/engine/check-grammars.sh and the CI "grammars" job regenerate the vendored
# parsers with this exact version. Install it into the nvm-managed Node prefix:
# that bin directory is already on PATH and lives under $HOME, so it persists in
# environment snapshots. Use an inline `--prefix` rather than `npm config set`
# so nothing is written to ~/.npmrc (a persisted prefix there makes nvm print a
# warning on every shell start). The base image's default global prefix is not
# writable, which is why the prefix must be given explicitly.
# ---------------------------------------------------------------------------
TS_VERSION="0.25.10"
if [ "$(tree-sitter --version 2>/dev/null | awk '{print $2}')" != "$TS_VERSION" ]; then
  node_prefix="$(dirname "$(dirname "$(command -v npm)")")"
  npm install -g --prefix "$node_prefix" "tree-sitter-cli@${TS_VERSION}"
fi
tree-sitter --version

# ---------------------------------------------------------------------------
# Rust workspace
# rust-toolchain.toml pins the stable channel plus rustfmt and clippy, so no
# explicit toolchain install is needed. Warm the dependency cache and target
# directory so the first `cargo test` in the agent is fast.
#
# The committed Cargo.lock is what cargo resolves, and CI builds with --locked.
# The build runs without it so that a checkout whose manifests are ahead of its
# lock still warms; the committed lock is restored afterwards to keep the
# working tree clean for the agent.
# ---------------------------------------------------------------------------
lock_backup="$(mktemp)"
cp Cargo.lock "$lock_backup"
cargo build --workspace
cp "$lock_backup" Cargo.lock
rm -f "$lock_backup"

echo "cloud-agent-install: done"
