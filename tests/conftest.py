"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (SRC, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

os.environ.setdefault("TERM_PROGRAM", "vscode")

_repo_patcher: patch | None = None
_original_find_repo_root = None


def _test_find_repo_root(start: Path | None = None) -> Path:
    """Pin default repo root for imports; honour env override and explicit *start*."""
    if start is not None:
        assert _original_find_repo_root is not None
        return _original_find_repo_root(start)
    override = os.environ.get("OPENTIDE_REPO_ROOT")
    if override:
        return Path(override)
    return ROOT


def pytest_configure(config: object) -> None:
    """Pin repo root before Engines modules resolve paths at import time."""
    global _repo_patcher, _original_find_repo_root
    import opentide.core.root as root_mod

    _original_find_repo_root = root_mod.find_repo_root
    _repo_patcher = patch.object(root_mod, "find_repo_root", _test_find_repo_root)
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
    from opentide.registry.discovery import OPENTIDE_DIR

    workspace = ROOT / TIDE_WORKSPACE_DIR
    workspace.mkdir(parents=True, exist_ok=True)
    for rel in (
        f"{OPENTIDE_DIR}/schemas",
        f"{OPENTIDE_DIR}/templates",
        f"{OPENTIDE_DIR}/exports",
        f"{OPENTIDE_DIR}/inflight",
        f"{OPENTIDE_DIR}/configurations",
        "objects/threats",
        "objects/objectives",
        "objects/rules",
        ".vscode",
    ):
        (workspace / rel).mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(workspace.resolve()))
    return workspace
