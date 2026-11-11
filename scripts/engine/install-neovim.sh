#!/usr/bin/env bash
# Installs Neovim for ci.yml's clients job (the headless smoke test,
# scripts/engine/nvim-smoke.lua) from Neovim's GitHub release, pinned by
# version and sha256 for each Linux architecture, instead of Ubuntu's apt
# archive: GitHub's runners could not reach Ubuntu's mirrors on 2026-11-11, and
# a pinned release does not move under the test.
#
#   scripts/engine/install-neovim.sh <prefix>     # then put <prefix>/bin on PATH
#
# To move to a new release, change `version` and both sha256 values together
# (sha256sum of https://github.com/neovim/neovim/releases/download/<version>/
# nvim-linux-<arch>.tar.gz); scripts/engine/test_release.py checks the pins.
set -euo pipefail

version=v0.12.6
case "$(uname -m)" in
  x86_64)
    arch=x86_64
    sha256=474430d53e6264f6d6dd18db42d6dc9df3a1b56ca9e88a325bbf860e1a811d87
    ;;
  aarch64 | arm64)
    arch=arm64
    sha256=8f1f64a0bdb97247034038c3823c6cbad5bdf9ecd5751b85494b71c3ee04c815
    ;;
  *)
    echo "install-neovim: no pinned Neovim release for $(uname -m)" >&2
    exit 1
    ;;
esac

prefix="${1:?usage: install-neovim.sh <prefix>}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tarball="$work/nvim-linux-${arch}.tar.gz"

curl --fail --silent --show-error --location --retry 3 --retry-all-errors \
  --connect-timeout 20 --max-time 300 --output "$tarball" \
  "https://github.com/neovim/neovim/releases/download/${version}/nvim-linux-${arch}.tar.gz"
echo "${sha256}  ${tarball}" | sha256sum --check --quiet -

mkdir -p "$prefix"
tar -xzf "$tarball" -C "$prefix" --strip-components=1
"$prefix/bin/nvim" --version | head -n 1
