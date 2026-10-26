"""Runtime environment helpers."""

from __future__ import annotations

import os

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
