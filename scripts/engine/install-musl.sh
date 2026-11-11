#!/usr/bin/env bash
# Installs musl's C toolchain wrapper, musl-gcc, for the engine's musl release
# builds (engine-release-build.yml): the linker cargo is given for
# *-unknown-linux-musl, and the C compiler the cc crate finds for tree-sitter's
# C sources. This is what Ubuntu's musl-tools package provides (musl's own
# musl-gcc wrapper around the system gcc, musl's headers, crt files and libc),
# built here from musl's release tarball so the release does not depend on
# Ubuntu's apt mirrors, which GitHub's runners could not reach on 2026-11-11.
#
#   scripts/engine/install-musl.sh <prefix>     # then put <prefix>/bin on PATH
#
# The tarball is pinned by sha256 and fetched from musl.libc.org, or from
# Debian's archive (the same upstream tarball, as musl_<version>.orig.tar.gz)
# when that host fails. To move to a new musl release, change `version` and
# `sha256` together (scripts/engine/test_release.py checks the pin's shape).
set -euo pipefail

version=1.2.6
sha256=d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a
urls=(
  "https://musl.libc.org/releases/musl-${version}.tar.gz"
  "https://deb.debian.org/debian/pool/main/m/musl/musl_${version}.orig.tar.gz"
)

prefix="${1:?usage: install-musl.sh <prefix>}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tarball="$work/musl-${version}.tar.gz"

fetched=""
for url in "${urls[@]}"; do
  rm -f "$tarball"
  if curl --fail --silent --show-error --location --retry 3 --retry-all-errors \
    --connect-timeout 20 --max-time 300 --output "$tarball" "$url"; then
    if echo "${sha256}  ${tarball}" | sha256sum --check --quiet -; then
      fetched="$url"
      break
    fi
    echo "install-musl: $url does not match the pinned sha256" >&2
  else
    echo "install-musl: could not download $url" >&2
  fi
done
if [[ -z "$fetched" ]]; then
  echo "install-musl: no source served musl ${version} with sha256 ${sha256}" >&2
  exit 1
fi
echo "install-musl: musl ${version} from ${fetched}"

tar -xzf "$tarball" -C "$work"
cd "$work/musl-${version}"
# --syslibdir: the dynamic loader's symlink goes under the prefix, not /lib, so
# no root is needed (the static binaries the release builds never use it).
./configure --prefix="$prefix" --syslibdir="$prefix/lib" >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
"$prefix/bin/musl-gcc" --version | head -n 1
