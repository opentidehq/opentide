"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (SRC, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

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


@pytest.fixture
def metadata() -> dict[str, Any]:
    return {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "schema": "rule::1.0",
        "version": 1,
        "created": "2026-01-01",
        "modified": "2026-01-02",
        "tlp": "clear",
    }


@pytest.fixture
def rule_payload(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "Test rule",
        "metadata": metadata,
        "description": "desc",
        "status": "STAGING",
        "severity": "High",
        "techniques": ["T1059"],
        "platforms": {},
    }


@pytest.fixture(autouse=True)
def _reset_opentide_registry() -> None:
    """Prevent tests from polluting singleton state."""
    yield
    from opentide.core.registry import OpenTide

    OpenTide._initialised = False  # noqa: SLF001
    OpenTide._objects_loaded = False  # noqa: SLF001
    OpenTide._index = None  # noqa: SLF001
    OpenTide._rules = {}
    OpenTide._threats = {}
    OpenTide._objectives = {}


@pytest.fixture
def tide_workspace(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect tide instance outputs into a repo-local workspace for portable CI."""
    from opentide.generation.artifact_gate import TIDE_WORKSPACE_DIR

    workspace = ROOT / TIDE_WORKSPACE_DIR
    workspace.mkdir(parents=True, exist_ok=True)
    for rel in (
        "Schemas",
        "Schemas/Templates",
        "Schemas/Configurations",
        "Schemas/Indexes",
        "Schemas/Exports",
        "Objects/Threat Vectors",
        "Objects/Detection Objectives",
        "Objects/Detection Rules",
        "Analytics",
        ".vscode",
    ):
        (workspace / rel).mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(workspace.resolve()))
    return workspace
