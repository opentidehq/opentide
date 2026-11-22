#!/usr/bin/env bash
# The release's smoke tests (.github/workflows/release-build.yml, `smoke`):
# each artifact installed the way a user installs it, on its own platform.
#
#   scripts/build/smoke_release.sh platform   on Linux and macOS, the binary
#       installer against the release assets (opentide-installer.sh), then
#       `opentide --version` (the release's version) and `opentide-lsp
#       --version` (no standalone binary ships for Windows: it installs from
#       PyPI or npm; on Windows, the check that no Windows binary or
#       installer is an asset); then, on every platform, every npm tarball
#       published to a throwaway local registry and `npm install
#       @opentide/opentide` in a clean project
#       (scripts/engine/npm-local-registry/test.mjs: npm chooses exactly this
#       platform's native package; npx, the SDK, runJson, tsc).
#   scripts/build/smoke_release.sh sdist      the PyPI dist's shape (one
#       version, the six cp310-abi3 wheels, one sdist), then `pip install` from
#       the sdist with the machine's Rust (the sdist leaves rust-toolchain.toml
#       out), as on a platform without a wheel, and scripts/build/smoke_package.py.
#   scripts/build/smoke_release.sh cargo      `cargo install opentide --features
#       cli` from the crate packages, before crates.io has this version (a patch
#       resolves each to its package: release.py crate-patch).
#
# Environment: SMOKE_ARTIFACTS (release-assets/, npm/, dist/, crates/ under
# it, as the job downloads them), VERSION (the binaries'), NPM_VERSION,
# PYPI_VERSION, CRATES_VERSION. The wheels' own smoke, on each platform, is
# build-packages.yml's `wheel-smoke`.
set -euo pipefail

kind="${1:?platform, sdist or cargo}"
artifacts="${SMOKE_ARTIFACTS:?}"
tmp="${RUNNER_TEMP:-$(mktemp -d)}"

case "${kind}" in
  platform)
    : "${VERSION:?}" "${NPM_VERSION:?}"
    assets="${artifacts}/release-assets"
    bin="${tmp}/bin"
    if [[ "${OS:-}" == "Windows_NT" ]]; then
      # No Windows binary or installer is a release asset: the release ships
      # none (scripts/engine/release.py BINARY_TARGETS).
      if compgen -G "${assets}/*.exe" >/dev/null || [[ -e "${assets}/opentide-installer.ps1" ]]; then
        echo "a Windows binary or installer is among the release assets" >&2
        exit 1
      fi
    else
      OPENTIDE_DOWNLOAD_URL="file://${assets}" OPENTIDE_INSTALL_DIR="${bin}" \
        sh "${assets}/opentide-installer.sh"
      out="$("${bin}/opentide" --version)"
      echo "${out}"
      grep -qF "${VERSION}" <<<"${out}" || { echo "opentide --version printed ${out}, not ${VERSION}" >&2; exit 1; }
      "${bin}/opentide-lsp" --version
    fi
    node scripts/engine/npm-local-registry/test.mjs --version "${NPM_VERSION}" --tarballs "${artifacts}/npm"
    ;;
  sdist)
    : "${PYPI_VERSION:?}"
    dist="${artifacts}/dist"
    ls -l "${dist}"
    python3 - "${dist}" "${PYPI_VERSION}" <<'PY'
import sys
from pathlib import Path

dist, expected = Path(sys.argv[1]), sys.argv[2]
built = sorted(p.name for p in dist.iterdir() if p.is_file())
wheels = [name for name in built if name.endswith(".whl")]
sdists = [name for name in built if name.endswith(".tar.gz")]
versions = {name.split("-")[1] for name in wheels} | {
    name.removesuffix(".tar.gz").rsplit("-", 1)[1] for name in sdists
}
tags = {
    "manylinux_2_28_x86_64", "manylinux_2_28_aarch64", "macosx_10_12_x86_64",
    "macosx_11_0_arm64", "win_amd64", "win_arm64",
}
problems = []
if len(sdists) != 1:
    problems.append(f"expected one sdist, found {sdists}")
if versions != {expected}:
    problems.append(f"built {sorted(versions)}, expected {expected}")
# A release's version is never a development build's.
if "dev" not in expected and any("dev" in v or "+" in v for v in versions):
    problems.append(f"a development version in a release: {sorted(versions)}")
if not all("-cp310-abi3-" in name for name in wheels):
    problems.append(f"a wheel is not cp310-abi3: {wheels}")
if any("musllinux" in name for name in wheels):
    problems.append(f"a musllinux wheel: {wheels}")
found = {name.removesuffix(".whl").rsplit("-", 1)[1] for name in wheels}
if found != tags or len(wheels) != len(tags):
    problems.append(f"expected one wheel for each of {sorted(tags)}, found {wheels}")
for problem in problems:
    print(f"::error::{problem}")
sys.exit(1 if problems else 0)
PY
    cargo --version
    python -m venv "${tmp}/venv"
    "${tmp}/venv/bin/python" -m pip install --quiet --no-binary opentide "${dist}"/opentide-*.tar.gz
    "${tmp}/venv/bin/python" -I scripts/build/smoke_package.py "${PYPI_VERSION}"
    ;;
  cargo)
    : "${CRATES_VERSION:?}"
    config="$(python3 scripts/engine/release.py crate-patch "${artifacts}/crates" "${tmp}/packages")"
    cargo install --config "${config}" --path "${tmp}/packages/opentide-${CRATES_VERSION}" \
      --features cli --debug --root "${tmp}/cargo"
    out="$("${tmp}/cargo/bin/opentide" --version)"
    echo "${out}"
    grep -qF "${CRATES_VERSION}" <<<"${out}" || { echo "opentide --version printed ${out}, not ${CRATES_VERSION}" >&2; exit 1; }
    ;;
  *)
    echo "smoke_release.sh: unknown kind ${kind} (platform, sdist or cargo)" >&2
    exit 2
    ;;
esac
