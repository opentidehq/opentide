#!/usr/bin/env bash
# Check out the two public YARA rule sets the release gate scans with, at pinned commits (#1743).
#
#   fetch-rules.sh DEST
#
# DEST/signature-base: Neo23x0/signature-base (Detection Rule License 1.1), DEST/protections-artifacts:
# elastic/protections-artifacts (Elastic License 2.0). Rules are read, never redistributed. A pin is a commit
# of the repository; the script fails when the checkout is not it. To move a pin, change it here, in a pull
# request that says why.
set -euo pipefail
dest="${1:?usage: fetch-rules.sh DEST}"
SIGNATURE_BASE_COMMIT="78d979eef87786a613659ee82e55abdd45572a78"
ELASTIC_COMMIT="418cfd9aaa89ffc4b6a55e3d01c384facf4fd548"

checkout() { # name url commit
  local name="$1" url="$2" commit="$3"
  git clone --quiet --filter=blob:none --no-checkout "${url}" "${dest}/${name}"
  git -C "${dest}/${name}" checkout --quiet "${commit}"
  local head
  head="$(git -C "${dest}/${name}" rev-parse HEAD)"
  case "${head}" in
    "${commit}"*) echo "${name} at ${head}" ;;
    *) echo "::error::${name} is at ${head}, not the pinned ${commit}" >&2; exit 1 ;;
  esac
}

mkdir -p "${dest}"
checkout signature-base https://github.com/Neo23x0/signature-base "${SIGNATURE_BASE_COMMIT}"
checkout protections-artifacts https://github.com/elastic/protections-artifacts "${ELASTIC_COMMIT}"
