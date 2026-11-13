#!/bin/sh
# Installs opentide's standalone binaries, `opentide` (the command line) and
# `opentide-lsp` (the language server), from one GitHub Release of
# opentidehq/opentide, on Linux (x86_64, aarch64; glibc) and macOS (Intel,
# Apple silicon). Each binary is checked against the release's SHA256SUMS
# before it is installed.
#
#   curl -fsSL https://github.com/opentidehq/opentide/releases/download/vX.Y.Z/opentide-installer.sh | sh
#
# The release workflow (.github/workflows/publish.yml) writes the release's
# tag into OPENTIDE_TAG below; the copy in the repository names none, and
# needs OPENTIDE_TAG set. Settings, from the environment:
#
#   OPENTIDE_INSTALL_DIR  where the binaries go (default: $HOME/.local/bin)
#   OPENTIDE_TAG          the release to install (default: this installer's)
#   OPENTIDE_DOWNLOAD_URL where the release's assets are (default: the GitHub
#                         Release of OPENTIDE_TAG); the workflow's smoke test
#                         points it at the assets it built (file://...)
#
# There are no musl (Alpine) binaries: the maintainer decided against musl
# builds (docs/internal/publishing.md). There, `pip install opentide` builds
# from the sdist.
set -eu

RELEASE_TAG="__OPENTIDE_TAG__"
tag="${OPENTIDE_TAG:-$RELEASE_TAG}"
case "$tag" in
  v[0-9]*) ;;
  *) echo "opentide-installer: set OPENTIDE_TAG to a release tag (vX.Y.Z)" >&2; exit 1 ;;
esac
base="${OPENTIDE_DOWNLOAD_URL:-https://github.com/opentidehq/opentide/releases/download/$tag}"
dir="${OPENTIDE_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux)
    if ldd --version 2>&1 | grep -qi musl; then
      echo "opentide-installer: no musl build is published; use \`pip install opentide\`" >&2
      exit 1
    fi
    os="unknown-linux-gnu" ;;
  Darwin) os="apple-darwin" ;;
  *) echo "opentide-installer: $(uname -s) is not supported; on Windows, use opentide-installer.ps1" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64" ;;
  aarch64 | arm64) arch="aarch64" ;;
  *) echo "opentide-installer: no build for $(uname -m)" >&2; exit 1 ;;
esac
target="$arch-$os"

fetch() {
  curl --proto '=https,file' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT INT TERM
fetch "$base/SHA256SUMS" "$scratch/SHA256SUMS"
# Every binary is downloaded and checked before any is installed.
for binary in opentide opentide-lsp; do
  asset="$binary-$tag-$target"
  fetch "$base/$asset" "$scratch/$asset"
  expected="$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1 }' "$scratch/SHA256SUMS")"
  if [ -z "$expected" ]; then
    echo "opentide-installer: SHA256SUMS lists no $asset" >&2
    exit 1
  fi
  actual="$(sha256 "$scratch/$asset")"
  if [ "$actual" != "$expected" ]; then
    echo "opentide-installer: $asset does not match SHA256SUMS" >&2
    exit 1
  fi
done
mkdir -p "$dir"
for binary in opentide opentide-lsp; do
  asset="$binary-$tag-$target"
  chmod 755 "$scratch/$asset"
  mv "$scratch/$asset" "$dir/$binary"
  echo "installed $dir/$binary ($tag, $target)"
done
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "add $dir to PATH to run opentide" ;;
esac
