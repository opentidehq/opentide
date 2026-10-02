#!/usr/bin/env bash
# Install pinned glint and gitlab-ci-verify binaries.
#
# glint lints pipeline structure offline (stages, needs, rules, required script).
# gitlab-ci-verify's Pipeline Lint API needs a GitLab project token, so CI runs
# it with --no-lint-api and uses the bundled ShellCheck on job scripts.
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: $0 DEST_DIR" >&2
  exit 2
fi

dest="$1"
mkdir -p "$dest"

case "$(uname -s)" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *)
    echo "unsupported operating system: $(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

glint_version="v0.5.1"
verify_version="v2.11.8"

case "${os}-${arch}" in
  linux-amd64)
    glint_sha="66a64ff6b0bc2cdfe86ba446ef2a20e5a551fd084df1185cba6bf07fdcda4e43"
    verify_sha="7a681c7388d319f9dde6aa74bbec0a22116f850ce88a0cca35d15bf2e7c5ad9f"
    ;;
  linux-arm64)
    glint_sha="e08415b5533643f8230757450eca399ffb59f2b33d7bb1c16afa4981c397f6de"
    verify_sha="b08951da000c4786976c91dd4685f9b47850530e7a09d3d90d45f29ebdc558fb"
    ;;
  darwin-amd64)
    glint_sha="bff20ffeba2f0887abfe51c87a5d2b0a4cdad25b320e5abdb7bacff0963f07fb"
    verify_sha="d98789d2a91c2bf1ba215a79844ae5746fb6959c82d71440478035a74b1c5c58"
    ;;
  darwin-arm64)
    glint_sha="858554c540a14dc5ae6ceaf4445f52bc34f11b3835f92d119e575d39747f7839"
    verify_sha="e1e9228e6e0be6f22a468bf3af692cacf2c9ca757e98bc589bae68ae238f0e29"
    ;;
esac

sha256_check() {
  local file="$1" expected="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "${expected}  ${file}" | sha256sum -c --status
  elif command -v shasum >/dev/null 2>&1; then
    echo "${expected}  ${file}" | shasum -a 256 -c --status
  else
    echo "sha256sum or shasum is required to verify downloads" >&2
    exit 1
  fi
}

install_one() {
  local name="$1" url="$2" hash="$3"
  local path="$dest/$name"
  if [[ -x "$path" ]] && sha256_check "$path" "$hash"; then
    return 0
  fi
  curl -fsSL -o "${path}.partial" "$url"
  sha256_check "${path}.partial" "$hash"
  chmod +x "${path}.partial"
  mv "${path}.partial" "$path"
}

install_one glint \
  "https://git.k3nny.fr/k3nny/glint/releases/download/${glint_version}/glint-${glint_version}-${os}-${arch}" \
  "$glint_sha"

install_one gitlab-ci-verify \
  "https://github.com/timo-reymann/gitlab-ci-verify/releases/download/${verify_version}/gitlab-ci-verify_${os}-${arch}" \
  "$verify_sha"
