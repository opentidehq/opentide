"""Runtime environment helpers."""

from __future__ import annotations

import os

from opentide.core.runtime import is_ci, is_debug, repo_root


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
