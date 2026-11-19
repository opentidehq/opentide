"""``scripts/engine/build-wasm.sh``: the artifacts are read where cargo wrote them.

AGENTS.md gives each worktree a target pool outside it (``CARGO_TARGET_DIR``):
cargo builds there, so the script must read the module there too, not from the
checkout's ``target/``, where it is missing or stale (smoke C11). The tools the
script runs (``cargo``, ``rustup``, ``node``) are stand-ins that record their
arguments, so no wasm toolchain is needed.
"""

from __future__ import annotations

import os
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

#: `cargo build` writes an empty module where cargo would; `rustup` does nothing.
CARGO = """#!/bin/sh
echo "cargo $*" >> "$CALLS"
mkdir -p "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release"
: > "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/opentide_wasm.wasm"
"""
RECORD = """#!/bin/sh
echo "$(basename "$0") $*" >> "$CALLS"
"""


def _run(tmp_path: Path, target_dir: str, cwd: Path) -> list[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, text in (("cargo", CARGO), ("rustup", RECORD), ("node", RECORD)):
        tool = bin_dir / name
        tool.write_text(text, encoding="utf-8", newline="\n")
        tool.chmod(0o755)
    calls = tmp_path / "calls.txt"
    env = {
        # No wasm-bindgen on PATH: the script skips the glue's smoke.
        "PATH": os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"]),
        "CALLS": str(calls),
        "CARGO_TARGET_DIR": target_dir,
        "HOME": str(tmp_path),
    }
    done = subprocess.run(
        ["bash", str(SCRIPT), "browser"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return calls.read_text(encoding="utf-8").splitlines()


def _smoked(calls: list[str]) -> Path:
    node = next(call for call in calls if call.startswith("node "))
    return Path(node.split()[-1])


def test_the_browser_module_is_read_from_cargo_target_dir(tmp_path: Path) -> None:
    pool = tmp_path / "pool"
    calls = _run(tmp_path, str(pool), cwd=tmp_path)
    assert _smoked(calls) == pool / "wasm32-unknown-unknown" / "release" / "opentide_wasm.wasm"


def test_a_relative_cargo_target_dir_is_read_from_the_working_directory(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    calls = _run(tmp_path, "pool", cwd=work)
    smoked = _smoked(calls)
    assert smoked == work / "pool" / "wasm32-unknown-unknown" / "release" / "opentide_wasm.wasm"
    assert smoked.is_file()
