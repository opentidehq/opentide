#!/usr/bin/env bash
# Scan the release artifacts with ClamAV: one clamd, on every core, over every tree given (#1743).
#
#   clamav-scan.sh REPORT TREE...
#
# clamd loads the databases freshclam fetched (CLAMAV_DATABASE, default /var/lib/clamav) with a config
# of its own, written here (not the package's /etc/clamav/clamd.conf, whose limits are not clamscan's):
# archives opened and nested to a depth of 30, 900M a file, 4000M a container, anything over a limit a
# detection, every other limit ClamAV's default, as clamscan's. `clamdscan --multiscan` deals each TREE's
# files to one thread per core. One engine scans them all, so content it has already found clean is a
# cache hit when it comes again: a wheel's members, scanned inside the wheel, are not scanned a second
# time when the extracted tree holds them, and the databases are loaded once (one clamscan per core,
# #1785, scanned that content once in each process that met it, each with its own copy of the databases).
#
# Two checks keep the result honest. Before the trees, a canary: the EICAR test string (assembled here,
# so this file is not one) in a zip inside a zip must be detected, or archive scanning is off and nothing
# the scan says means anything. After them, clamd's log (`LogClean`) must hold a verdict for every
# regular file of every TREE (scripts/av/clamd_verdicts.py): a file the daemon did not reach fails.
#
# REPORT receives the engine and database versions, each detection and each tree's summary. Exit
# status: 0 clean, 1 a detection, 2 the scan could not run, its canary was not detected, or a file has
# no verdict.
set -euo pipefail
report="${1:?usage: clamav-scan.sh REPORT TREE...}"
shift
if [ "$#" -eq 0 ]; then
  echo "usage: clamav-scan.sh REPORT TREE..." >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
database="${CLAMAV_DATABASE:-/var/lib/clamav}"

fail() { # message: the scan could not be trusted
  echo "::error::$1"
  echo "$1" >&2
  exit 2
}

trees=()
for tree in "$@"; do
  [ -d "${tree}" ] || fail "no such directory: ${tree}"
  # clamd logs each file under the path it was given: give it the one clamd_verdicts.py resolves.
  trees+=("$(realpath "${tree}")")
done

# A directory of this run's own: its socket can only be answered by the clamd started here.
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/clamd.XXXXXX")"
conf="${work}/clamd.conf"
log="${work}/clamd.log"
cat > "${conf}" <<EOF
DatabaseDirectory ${database}
LocalSocket ${work}/clamd.sock
Foreground yes
LogFile ${log}
LogFileMaxSize 0
LogClean yes
LogTime no
MaxThreads $(nproc)
ScanArchive yes
MaxFileSize 900M
MaxScanSize 4000M
MaxRecursion 30
MaxDirectoryRecursion 64
AlertExceedsMax yes
EOF

# In the foreground, clamd echoes its log (a line a file, with LogClean) to the console: keep that
# out of the job's log, and show it only when clamd fails to start.
clamd --config-file="${conf}" > "${work}/clamd.out" 2>&1 &
pid="$!"
trap 'kill "${pid}" 2>/dev/null || true; wait "${pid}" 2>/dev/null || true; rm -rf "${work}"' EXIT

# The databases take a few seconds to load; clamd answers a PING once they have.
ready=""
for _ in $(seq 1 600); do
  if ! kill -0 "${pid}" 2>/dev/null; then
    cat "${work}/clamd.out" >&2 2>/dev/null || true
    fail "clamd exited before it was ready (its output is above)"
  fi
  if clamdscan --config-file="${conf}" --ping 1 >/dev/null 2>&1; then
    ready="yes"
    break
  fi
  sleep 0.5
done
[ -n "${ready}" ] || fail "clamd did not answer within 300 s"

: > "${report}"
echo "clamd: $(clamdscan --config-file="${conf}" --version)" | tee -a "${report}"

canary="${work}/canary"
mkdir -p "${canary}"
python3 - "${canary}/canary.zip" <<'PY'
import io
import sys
import zipfile

eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
inner = io.BytesIO()
with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("eicar.com", eicar)
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("inner.zip", inner.getvalue())
PY
status=0
canary_out="$(clamdscan --config-file="${conf}" --no-summary "${canary}/canary.zip" 2>&1)" || status="$?"
echo "canary: ${canary_out}"
if [ "${status}" -ne 1 ] || ! grep -q 'Eicar-Test-Signature FOUND' <<<"${canary_out}"; then
  fail "the canary (the EICAR test string in a zip in a zip) was not detected (clamdscan exited ${status}): nothing this scan says can be trusted"
fi

status=0
for tree in "${trees[@]}"; do
  echo "::group::clamdscan ${tree}"
  scanned=0
  clamdscan --config-file="${conf}" --multiscan --infected "${tree}" 2>&1 | tee -a "${report}" \
    || scanned="${PIPESTATUS[0]}"
  echo "::endgroup::"
  # clamdscan exits 0 clean, 1 a detection, 2 an error: an error outranks a detection.
  case "${scanned}" in
    0) ;;
    1) [ "${status}" -eq 2 ] || status=1 ;;
    *) status=2 ;;
  esac
done

python3 "${here}/clamd_verdicts.py" --log "${log}" "${trees[@]}" 2>&1 | tee -a "${report}" \
  || status=2
exit "${status}"
