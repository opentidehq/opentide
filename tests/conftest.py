"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Engine modules expect a recognised CI/debug context at import time.
os.environ.setdefault("TERM_PROGRAM", "vscode")

_repo_patcher: patch | None = None


def pytest_configure(config: object) -> None:
    """Pin git repo root before Engines modules resolve paths at import time."""
    global _repo_patcher
    mock_repo = MagicMock()
    mock_repo.working_dir = str(ROOT)
    _repo_patcher = patch("git.Repo", return_value=mock_repo)
    _repo_patcher.start()


def pytest_unconfigure(config: object) -> None:
    global _repo_patcher
    if _repo_patcher is not None:
        _repo_patcher.stop()
        _repo_patcher = None
