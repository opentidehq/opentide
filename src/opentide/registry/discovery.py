"""Detect OpenTide detection workspaces."""

from __future__ import annotations

import os
from pathlib import Path

from opentide.core.root import get_repo_root

OPENTIDE_DIR = ".opentide"


def discover_workspace() -> Path:
    """Return detection workspace root (``OPENTIDE_TIDE_WORKSPACE``, fixture, or repo root)."""
    workspace_env = os.environ.get("OPENTIDE_TIDE_WORKSPACE")
    if workspace_env:
        return Path(workspace_env).resolve()
    repo = get_repo_root()
    if (repo / "objects").is_dir():
        return repo.resolve()
    fixture = repo / "tests/fixtures/generation/tide_workspace"
    if fixture.is_dir():
        return fixture.resolve()
    return repo.resolve()


def opentide_dir(workspace: Path | None = None) -> Path:
    """Return ``.opentide/`` directory within the workspace."""
    return (workspace or discover_workspace()) / OPENTIDE_DIR


def is_opentide_workspace(root: Path | None = None) -> bool:
    """True when ``.opentide/`` exists in the workspace."""
    base = root or discover_workspace()
    return (base / OPENTIDE_DIR).is_dir()


def client_configurations_dir(workspace: Path | None = None) -> Path:
    """Client configuration overrides (``.opentide/configurations/``)."""
    base = workspace or discover_workspace()
    return base / OPENTIDE_DIR / "configurations"
