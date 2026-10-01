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

case "$arch" in
  amd64)
    glint_sha="66a64ff6b0bc2cdfe86ba446ef2a20e5a551fd084df1185cba6bf07fdcda4e43"
    verify_sha="7a681c7388d319f9dde6aa74bbec0a22116f850ce88a0cca35d15bf2e7c5ad9f"
    ;;
  arm64)
    glint_sha="e08415b5533643f8230757450eca399ffb59f2b33d7bb1c16afa4981c397f6de"
    verify_sha="b08951da000c4786976c91dd4685f9b47850530e7a09d3d90d45f29ebdc558fb"
    ;;
esac

install_one() {
  local name="$1" url="$2" hash="$3"
  local path="$dest/$name"
  if [[ -x "$path" ]] && echo "${hash}  ${path}" | sha256sum -c --status; then
    return 0
  fi
  curl -fsSL -o "${path}.partial" "$url"
  echo "${hash}  ${path}.partial" | sha256sum -c --status
  chmod +x "${path}.partial"
  mv "${path}.partial" "$path"
}

install_one glint \
  "https://git.k3nny.fr/k3nny/glint/releases/download/${glint_version}/glint-${glint_version}-linux-${arch}" \
  "$glint_sha"

install_one gitlab-ci-verify \
  "https://github.com/timo-reymann/gitlab-ci-verify/releases/download/${verify_version}/gitlab-ci-verify_linux-${arch}" \
  "$verify_sha"
