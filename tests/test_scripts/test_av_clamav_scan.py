"""The ClamAV job's script (scripts/av/clamav-scan.sh, #1743), run against stub daemons.

The real engine runs only in the release tier. These tests hold the script's own logic with a
stub `clamd` and `clamdscan` first on PATH: the exit status (0 clean, 1 a detection, 2 a scan
that cannot be trusted), the canary it must see detected (the stub opens zips, as clamd does, so
a canary that is not the EICAR string in a zip in a zip is missed), the verdict for every file,
the limits it gives clamd, and the daemon it leaves behind (none).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the gate's script runs on the Linux runners only"
)

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "av" / "clamav-scan.sh"

_SETTINGS = """
def settings(argv):
    conf = next(a.split("=", 1)[1] for a in argv if a.startswith("--config-file="))
    with open(conf, encoding="utf-8") as handle:
        return dict(line.split(" ", 1) for line in handle.read().splitlines() if " " in line)
"""

# A clamd that records its config and pid, makes its "socket" and waits to be stopped.
CLAMD = (
    _SETTINGS
    + """
import os, shutil, signal, sys, time
conf = settings(sys.argv[1:])
record = os.environ["STUB_RECORD"]
if os.environ.get("STUB_CLAMD_FAIL"):
    print("ERROR: Can't open the databases", flush=True)
    sys.exit(1)
shutil.copy(next(a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--config-file=")),
            os.path.join(record, "clamd.conf"))
with open(os.path.join(record, "clamd.pid"), "w") as handle:
    handle.write(str(os.getpid()))
with open(conf["LogFile"], "a", encoding="utf-8") as log:
    log.write("+++ Started\\n")
    if os.environ.get("STUB_WARN"):
        log.write("LibClamAV Warning: stub warning\\n")
open(conf["LocalSocket"], "w").close()
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True:
    time.sleep(0.1)
"""
)

# A clamdscan that walks what it is given and logs a verdict per file, as clamd's LogClean does.
CLAMDSCAN = (
    _SETTINGS
    + """
import io, os, sys, zipfile
argv = sys.argv[1:]
conf = settings(argv)
if not os.path.exists(conf["LocalSocket"]):
    print("ERROR: Could not connect to clamd")
    sys.exit(2)
if "--ping" in argv:
    sys.exit(0)
if "--version" in argv:
    print("ClamAV 1.5.4/0/stub")
    sys.exit(0)
EICAR = b"X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def has_eicar(blob):
    if blob == EICAR:
        return True
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        return False
    return any(has_eicar(archive.read(name)) for name in archive.namelist())

def verdict(path):
    marker = os.environ.get("STUB_INFECTED")
    if marker and marker in path:
        return "Stub.Detection"
    if not os.environ.get("STUB_BLIND") and has_eicar(open(path, "rb").read()):
        return "Eicar-Test-Signature"
    return None

target = argv[-1]
paths = [target] if os.path.isfile(target) else sorted(
    os.path.join(d, n) for d, _, names in os.walk(target) for n in names)
found = 0
with open(conf["LogFile"], "a", encoding="utf-8") as log:
    for path in paths:
        if os.environ.get("STUB_SKIP") and os.environ["STUB_SKIP"] in path:
            continue
        signature = verdict(path)
        line = f"{path}: {signature} FOUND" if signature else f"{path}: OK"
        log.write(line + "\\n")
        if signature or "--infected" not in argv:
            print(line)
        found += bool(signature)
print(f"Infected files: {found}")
forced = os.environ.get("STUB_SCAN_EXIT")
sys.exit(int(forced) if forced and "--multiscan" in argv else (1 if found else 0))
"""
)


def _prepare(tmp_path: Path) -> list[str]:
    """The stubs first on PATH and two trees as the gate has them; once per test directory."""
    bin_dir = tmp_path / "bin"
    if not bin_dir.exists():
        bin_dir.mkdir()
        for name, body in (("clamd", CLAMD), ("clamdscan", CLAMDSCAN)):
            stub = bin_dir / name
            stub.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
            stub.chmod(0o755)
        extracted = tmp_path / "av-extracted" / "pkg.whl.d" / "opentide"
        extracted.mkdir(parents=True)
        (tmp_path / "av-artifacts").mkdir()
        (tmp_path / "av-artifacts" / "pkg.whl").write_bytes(b"wheel")
        (extracted / "_native.so").write_bytes(b"binary")
        (extracted / "py.typed").write_bytes(b"")
    return [str(tmp_path / "av-artifacts"), str(tmp_path / "av-extracted")]


def _scan(tmp_path: Path, **env: str) -> tuple[subprocess.CompletedProcess[str], Path]:
    trees = _prepare(tmp_path)
    record = tmp_path / "record"
    record.mkdir(exist_ok=True)
    report = tmp_path / "clamav.txt"
    environment = {
        **os.environ,
        "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
        "STUB_RECORD": str(record),
        **env,
    }
    result = subprocess.run(
        ["bash", str(SCRIPT), str(report), *trees],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return result, record


def _daemon_stopped(record: Path) -> None:
    pid = int((record / "clamd.pid").read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_clean_trees_pass_with_a_verdict_for_every_file(tmp_path: Path) -> None:
    result, record = _scan(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "canary: " in result.stdout and "Eicar-Test-Signature FOUND" in result.stdout
    report = (tmp_path / "clamav.txt").read_text(encoding="utf-8")
    assert "clamd: ClamAV 1.5.4/0/stub" in report
    assert f"{tmp_path / 'av-artifacts'}: 1 files, 1 with a verdict" in report
    assert f"{tmp_path / 'av-extracted'}: 2 files, 2 with a verdict" in report
    _daemon_stopped(record)


def test_clamd_gets_the_limits_clamscan_had_and_a_thread_per_core_plus_one(
    tmp_path: Path,
) -> None:
    result, record = _scan(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    conf = (record / "clamd.conf").read_text(encoding="utf-8").splitlines()
    cores = int(subprocess.run(["nproc"], capture_output=True, text=True, check=True).stdout)
    for line in (
        "ScanArchive yes",
        "MaxFileSize 900M",
        "MaxScanSize 4000M",
        "MaxRecursion 30",
        "AlertExceedsMax yes",
        "LogClean yes",
        "LogTime no",
        "LogFileMaxSize 0",
        # A multiscan holds one thread of the pool to deal the files out.
        f"MaxThreads {cores + 1}",
    ):
        assert line in conf, line
    # Under /tmp: Ubuntu's AppArmor profile lets clamd write nowhere else of ours.
    socket = next(line for line in conf if line.startswith("LocalSocket "))
    assert socket.split(" ", 1)[1].startswith("/tmp/opentide-clamd.")


def test_a_detection_exits_1_and_is_in_the_report(tmp_path: Path) -> None:
    result, record = _scan(tmp_path, STUB_INFECTED="_native.so")
    assert result.returncode == 1, result.stdout + result.stderr
    report = (tmp_path / "clamav.txt").read_text(encoding="utf-8")
    assert "_native.so: Stub.Detection FOUND" in report
    _daemon_stopped(record)


def test_a_scan_error_exits_2_even_beside_a_detection(tmp_path: Path) -> None:
    result, _ = _scan(tmp_path, STUB_SCAN_EXIT="2")
    assert result.returncode == 2, result.stdout + result.stderr
    result, _ = _scan(tmp_path, STUB_SCAN_EXIT="2", STUB_INFECTED="_native.so")
    assert result.returncode == 2, result.stdout + result.stderr


def test_a_missed_canary_exits_2_before_any_tree_is_scanned(tmp_path: Path) -> None:
    result, record = _scan(tmp_path, STUB_BLIND="1")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "the canary" in result.stderr
    assert "with a verdict" not in result.stdout
    _daemon_stopped(record)


def test_a_file_without_a_verdict_exits_2_and_is_named(tmp_path: Path) -> None:
    result, _ = _scan(tmp_path, STUB_SKIP="py.typed")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "no verdict for" in result.stdout and "py.typed" in result.stdout


def test_a_clamd_that_does_not_start_exits_2_with_its_output(tmp_path: Path) -> None:
    result, _ = _scan(tmp_path, STUB_CLAMD_FAIL="1")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "Can't open the databases" in result.stderr
    assert "clamd exited before it was ready" in result.stderr


def test_clamds_warnings_reach_the_report(tmp_path: Path) -> None:
    result, _ = _scan(tmp_path, STUB_WARN="1")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "LibClamAV Warning: stub warning" in (tmp_path / "clamav.txt").read_text(
        encoding="utf-8"
    )


def test_a_tree_that_is_not_a_directory_exits_2(tmp_path: Path) -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path / "r.txt"), str(tmp_path / "missing")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 2
    assert "no such directory" in result.stderr
