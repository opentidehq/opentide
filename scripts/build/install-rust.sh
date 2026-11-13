#!/usr/bin/env bash
# Install the Rust that the packages build with: rust-toolchain.toml's release
# with the minimal profile (rustc, cargo, rust-std; no rustfmt, clippy or
# docs), plus each target named on the command line. Then name that release in
# RUSTUP_TOOLCHAIN, for this script and, in GitHub Actions, for every later
# step (GITHUB_ENV).
#
# Why: in a checkout, rustup reads rust-toolchain.toml and installs its
# release with the file's components the first time a build runs rustc or
# cargo. A wheel or npm-native build that did that mid-build failed now and
# then, on clippy ("detected conflict: 'bin/cargo-clippy'", linux-arm64) or
# on a release with no cargo yet ("'cargo' is not installed for the
# toolchain", macos-arm64). With the release installed here and named in
# RUSTUP_TOOLCHAIN, rustup never reads the file during the build.
#
# usage: scripts/build/install-rust.sh [TARGET ...]
# tests/test_ci/test_rust_toolchain.py holds the workflows to it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
channel="$(sed -n 's/^channel *= *"\([^"]*\)".*$/\1/p' "${root}/rust-toolchain.toml")"
if [[ ! "${channel}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "install-rust.sh: rust-toolchain.toml names no release (channel '${channel}')" >&2
  exit 1
fi

export RUSTUP_TOOLCHAIN="${channel}"
rustup toolchain install "${channel}" --profile minimal --no-self-update
for target in "$@"; do
  rustup target add --toolchain "${channel}" "${target}"
done
rustc --version
cargo --version

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "RUSTUP_TOOLCHAIN=${channel}" >> "${GITHUB_ENV}"
fi
