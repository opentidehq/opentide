"""``scripts/engine/build-wasm.sh``: the artifacts are read where cargo wrote them.

AGENTS.md gives each worktree a target pool outside it (``CARGO_TARGET_DIR``):
cargo builds there, so the script must read every artifact there too, not from
the checkout's ``target/``, where it is missing or stale (smoke C11). The tools
the script runs (``cargo``, ``rustup``, ``node``, ``wasm-bindgen``) are
stand-ins that record their arguments, on a ``PATH`` that holds them and the
few system tools the script needs, so no wasm toolchain is needed and none
installed on the machine is run.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "engine" / "build-wasm.sh"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="the script is bash, run on Linux and macOS",
)

#: `cargo build` writes an empty artifact where cargo would write the one its
#: arguments name: under $CARGO_TARGET_DIR, or target/ in the working folder.
CARGO = """#!/bin/sh
echo "cargo $*" >> "$CALLS"
out="${CARGO_TARGET_DIR:-target}"
case "$*" in
  *opentide-wasm*) file="$out/wasm32-unknown-unknown/release/opentide_wasm.wasm" ;;
  *opentide-lsp*) file="$out/wasm32-wasip1/release/opentide-lsp.wasm" ;;
  *opentide-cli*) file="$out/wasm32-wasip1/wasi/opentide-cli.wasm" ;;
  *) exit 0 ;;
esac
mkdir -p "$(dirname "$file")"
: > "$file"
"""
RECORD = """#!/bin/sh
echo "$(basename "$0") $*" >> "$CALLS"
"""
#: The system tools the script runs besides the stand-ins.
SYSTEM = ("dirname", "basename", "cp", "wc", "gzip", "mkdir", "cat")


def _run(tmp_path: Path, target: str, target_dir: str, cwd: Path) -> list[str]:
    bin_dir = tmp_path / "bin"
    if not bin_dir.exists():
        bin_dir.mkdir()
        for name, text in (
            ("cargo", CARGO),
            ("rustup", RECORD),
            ("node", RECORD),
            ("wasm-bindgen", RECORD),
        ):
            tool = bin_dir / name
            tool.write_text(text, encoding="utf-8", newline="\n")
            tool.chmod(0o755)
        for name in SYSTEM:
            found = shutil.which(name)
            assert found is not None, name
            (bin_dir / name).symlink_to(found)
    calls = tmp_path / "calls.txt"
    calls.unlink(missing_ok=True)
    sdk = tmp_path / "wasi-sdk"
    sdk.mkdir(exist_ok=True)
    env = {
        "PATH": str(bin_dir),
        "CALLS": str(calls),
        "CARGO_TARGET_DIR": target_dir,
        "HOME": str(tmp_path),
        # `cli`: an install of wasi-sdk is given, so nothing is downloaded.
        "WASI_SDK_PATH": str(sdk),
    }
    done = subprocess.run(
        [shutil.which("bash") or "bash", str(SCRIPT), target],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return calls.read_text(encoding="utf-8").splitlines()


def _arguments(calls: list[str], tool: str) -> list[list[str]]:
    return [call.split()[1:] for call in calls if call.split()[0] == tool]


@pytest.fixture(params=["absolute", "relative"])
def pool(request: pytest.FixtureRequest, tmp_path: Path) -> tuple[str, Path, Path]:
    """CARGO_TARGET_DIR as given, the folder the script runs in, and the pool
    cargo writes to: a relative one is read from the working folder."""
    work = tmp_path / "work"
    work.mkdir()
    if request.param == "absolute":
        return str(tmp_path / "pool"), work, tmp_path / "pool"
    return "pool", work, work / "pool"


def test_the_browser_module_and_its_glue_are_read_from_the_pool(
    tmp_path: Path, pool: tuple[str, Path, Path]
) -> None:
    given, work, target = pool
    calls = _run(tmp_path, "browser", given, work)
    module = target / "wasm32-unknown-unknown" / "release" / "opentide_wasm.wasm"
    glue = target / "wasm-bindgen"
    assert ["--target", "nodejs", "--out-dir", str(glue), str(module)] in _arguments(
        calls, "wasm-bindgen"
    )
    smoked = _arguments(calls, "node")
    assert smoked[0][-2:] == ["imports", str(module)]
    assert smoked[1][-2:] == ["browser", str(glue / "opentide_wasm.js")]


def test_the_wasi_server_is_read_from_the_pool(
    tmp_path: Path, pool: tuple[str, Path, Path]
) -> None:
    given, work, target = pool
    calls = _run(tmp_path, "wasi", given, work)
    server = target / "wasm32-wasip1" / "release" / "opentide-lsp.wasm"
    assert _arguments(calls, "node")[0][-2:] == ["wasi", str(server)]


def test_the_wasi_command_line_is_read_and_written_in_the_pool(
    tmp_path: Path, pool: tuple[str, Path, Path]
) -> None:
    given, work, target = pool
    _run(tmp_path, "cli", given, work)
    assert (target / "wasm32-wasip1" / "wasi" / "opentide.wasm").is_file()
