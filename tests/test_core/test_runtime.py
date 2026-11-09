"""Runtime environment helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from opentide.core.runtime import debug_requested, is_ci, is_debug, repo_root


def test_runtime_is_debug_vscode() -> None:
    os.environ["TERM_PROGRAM"] = "vscode"
    assert is_debug() is True
    del os.environ["TERM_PROGRAM"]


def test_runtime_is_ci() -> None:
    os.environ["CI"] = "true"
    assert is_ci() is True
    del os.environ["CI"]


def test_repo_root_is_path() -> None:
    root = repo_root()
    assert root.is_dir()
    assert (root / "pyproject.toml").is_file()


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        pytest.param({"OPENTIDE_DEBUG": "1"}, True, id="opentide-debug"),
        pytest.param({"OPENTIDE_DEBUG": "0", "DEBUG": "True"}, False, id="opentide-debug-wins"),
        pytest.param({"OPENTIDE_DEBUG": "off", "TERM_PROGRAM": "vscode"}, True, id="vscode"),
        pytest.param({"OPENTIDE_DEBUG": "*", "DEBUG": "True"}, True, id="not-boolean-falls-back"),
        pytest.param({"DEBUG": "True"}, True, id="legacy-debug"),
        pytest.param({"DEBUG": "*"}, False, id="node-debug"),
        pytest.param({}, False, id="unset"),
    ],
)
def test_is_debug_reads_opentide_debug_first(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], expected: bool
) -> None:
    for name in ("OPENTIDE_DEBUG", "DEBUG", "TERM_PROGRAM"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert is_debug() is expected


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"DEBUG": "yes"}, True),
        ({"DEBUG": "*"}, False),
        ({"OPENTIDE_DEBUG": "false", "DEBUG": "1"}, False),
        ({"OPENTIDE_DEBUG": "on"}, True),
    ],
)
def test_debug_requested(env: dict[str, str], expected: bool) -> None:
    assert debug_requested(env) is expected


_LEAK_PROBE = """
from pathlib import Path

from opentide.core.root import get_repo_root

SEEN: list[Path] = []


def test_a_sets_a_root(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))
    get_repo_root.cache_clear()
    SEEN.append(get_repo_root())
    assert SEEN[0] == tmp_path


def test_b_does_not_inherit_it():
    assert SEEN, "test_a_sets_a_root did not run first"
    assert get_repo_root() != SEEN[0]
"""


def test_a_cached_root_does_not_outlive_the_test_that_set_it(tmp_path: Path) -> None:
    """A test that points ``OPENTIDE_REPO_ROOT`` at its ``tmp_path`` must not leave
    the cached root behind: the next test in the worker would resolve the repository
    to a deleted directory (the order-dependent ``test_repo_root_is_path`` failure)."""
    probe = tmp_path / "test_probe.py"
    probe.write_text(_LEAK_PROBE, encoding="utf-8")
    root = Path(__file__).resolve().parents[2]
    env = {k: v for k, v in os.environ.items() if k != "OPENTIDE_REPO_ROOT"}
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:xdist",
            "-p",
            "no:randomly",
            "--no-cov",
            "-p",
            "tests.conftest",
            "--rootdir",
            str(tmp_path),
            "--confcutdir",
            str(tmp_path),
            str(probe),
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "2 passed" in run.stdout
