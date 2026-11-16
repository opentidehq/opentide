#!/usr/bin/env bash
# Cloud Agent environment bootstrap for the opentide language server.
# Idempotent: safe to run repeatedly and against a warm/cached checkout.
set -euo pipefail
cd "$(dirname "$0")/../.."

# ---------------------------------------------------------------------------
# Rust workspace
# rust-toolchain.toml pins one Rust release plus rustfmt and clippy;
# `rustup toolchain install` with no name installs exactly that. Then warm the
# dependency cache and target directory so the first `cargo test` in the agent
# is fast.
#
# The committed Cargo.lock is what cargo resolves, and CI builds with --locked.
# The build runs without it so that a checkout whose manifests are ahead of its
# lock still warms; the committed lock is restored afterwards to keep the
# working tree clean for the agent.
# ---------------------------------------------------------------------------
rustup toolchain install --profile minimal --no-self-update
lock_backup="$(mktemp)"
cp Cargo.lock "$lock_backup"
cargo build --workspace
cp "$lock_backup" Cargo.lock
rm -f "$lock_backup"

echo "cloud-agent-install: done"
