"""Tests for workspace discovery."""

from __future__ import annotations

from collections.abc import Iterator
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


def _workspace(path: Path) -> Path:
    (path / ".opentide").mkdir(parents=True)
    (path / "objects" / "rules").mkdir(parents=True)
    return path


@pytest.fixture
def discovered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    """The workspace cwd discovery finds, with no path exported."""
    import opentide.core.root as root_mod

    found = _workspace(tmp_path / "found")
    monkeypatch.setattr(root_mod, "find_workspace_root", lambda start=None: found)
    monkeypatch.delenv("OPENTIDE_REPO_ROOT", raising=False)
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    root_mod.get_repo_root.cache_clear()
    yield found
    root_mod.get_repo_root.cache_clear()


def test_discover_workspace_uses_the_discovered_workspace(discovered: Path) -> None:
    assert discover_workspace() == discovered.resolve()


@pytest.mark.parametrize("variable", ["OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"])
def test_exported_paths_beat_discovery(
    discovered: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, variable: str
) -> None:
    exported = _workspace(tmp_path / "exported")
    monkeypatch.setenv(variable, str(exported))
    assert discover_workspace() == exported.resolve()


def test_discover_workspace_keeps_the_dev_fixture_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The opentide checkout has ``.opentide/`` but no ``objects/`` of its own."""
    from opentide.core.root import get_repo_root

    checkout = tmp_path / "opentide"
    (checkout / ".opentide").mkdir(parents=True)
    fixture = checkout / "tests/fixtures/generation/tide_workspace"
    fixture.mkdir(parents=True)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(checkout))
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    get_repo_root.cache_clear()
    try:
        assert discover_workspace() == fixture.resolve()
    finally:
        get_repo_root.cache_clear()
