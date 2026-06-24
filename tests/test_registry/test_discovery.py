"""Tests for workspace discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.registry.discovery import discover_workspace


def test_discover_workspace_uses_repo_root_when_no_fixture_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    detection_repo = tmp_path / "client"
    detection_repo.mkdir()
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(detection_repo))
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    from opentide.core.root import get_repo_root

    get_repo_root.cache_clear()
    assert discover_workspace() == detection_repo.resolve()
    get_repo_root.cache_clear()


def test_discover_workspace_honours_tide_workspace_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(workspace))
    assert discover_workspace() == workspace.resolve()
