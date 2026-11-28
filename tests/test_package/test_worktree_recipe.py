"""The parallel-agents recipe in AGENTS.md, run as written.

Agents copy its shell lines verbatim, so the lines are tested, not paraphrased.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SECTION = "## Parallel agents: worktrees and target pools"


def _recipe() -> list[str]:
    text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    section = text.split(SECTION, 1)[1].split("\n## ", 1)[0]
    block = re.search(r"```bash\n(.*?)```", section, re.DOTALL)
    assert block is not None, "the section has a bash block"
    return block.group(1).splitlines()


def _line(prefix: str) -> str:
    """The recipe line that starts with ``prefix``, its trailing comment dropped."""
    found = [line for line in _recipe() if line.startswith(prefix)]
    assert len(found) == 1, (prefix, found)
    return found[0].split("  #", 1)[0].strip()


@pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("git") and shutil.which("xargs")),
    reason="needs bash, git and xargs",
)
def test_refreshing_mtimes_recreates_no_deleted_file(tmp_path: Path) -> None:
    """The hand-over line only refreshes the modification times of the tracked files that
    exist: a file deleted in the worktree (without `git rm`) must not come back empty,
    or `git commit -a` commits an empty file instead of the deletion."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, env=env)
    (tmp_path / "kept.rs").write_text("fn kept() {}\n", encoding="utf-8")
    (tmp_path / "gone.rs").write_text("fn gone() {}\n", encoding="utf-8")
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "gone.snap").write_text("snapshot\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, env=env)
    (tmp_path / "gone.rs").unlink()
    shutil.rmtree(tmp_path / "dir")
    os.utime(tmp_path / "kept.rs", (1_000_000_000, 1_000_000_000))

    subprocess.run(
        ["bash", "-c", f"set -euo pipefail; {_line('git ls-files')}"],
        cwd=tmp_path,
        check=True,
        env=env,
    )

    assert not (tmp_path / "gone.rs").exists()
    assert not (tmp_path / "dir").exists()
    assert (tmp_path / "kept.rs").stat().st_mtime > 1_000_000_000
    assert (tmp_path / "kept.rs").read_text(encoding="utf-8") == "fn kept() {}\n"


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_the_target_pool_is_never_a_default(tmp_path: Path) -> None:
    """Two agents that copy the recipe as it is must not share a pool: the line that sets
    CARGO_TARGET_DIR fails until POOL names one."""
    line = _line("export CARGO_TARGET_DIR=")
    env = {key: value for key, value in os.environ.items() if key != "POOL"}
    script = f'{line}; printf %s "$CARGO_TARGET_DIR"'
    unset = subprocess.run(
        ["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True
    )
    assert unset.returncode != 0
    assert unset.stdout == ""
    assert "POOL" in unset.stderr

    named = subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env={**env, "POOL": "pool-b"},
        capture_output=True,
        text=True,
        check=True,
    )
    assert named.stdout == f"{tmp_path.parent.resolve()}/.target/pool-b"
