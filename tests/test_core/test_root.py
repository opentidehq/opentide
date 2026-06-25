"""Data path resolution and enabled systems."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.core.files import resolve_configurations, resolve_paths
from opentide.core.root import find_repo_root, get_data_root, get_repo_root
from opentide.platforms.enabled import enabled_systems


@pytest.fixture(autouse=True)
def _clear_root_caches() -> None:
    get_data_root.cache_clear()
    get_repo_root.cache_clear()
    yield
    get_data_root.cache_clear()
    get_repo_root.cache_clear()


def test_resolve_configurations_includes_bundled_platforms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    configs = resolve_configurations()
    systems = configs.get("systems", {})
    assert "sentinel" in systems
    assert systems["sentinel"]["platform"]["identifier"] == "sentinel"


def test_resolve_paths_uses_bundled_vocabulary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    paths = resolve_paths()
    assert paths["vocabularies"] == get_data_root() / "vocabulary"
    assert paths["resources"] == get_data_root() / "external"
    assert paths["platform_configs"] == get_data_root() / "configurations" / "platforms"


def test_enabled_systems_reads_merged_config(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    systems = enabled_systems()
    assert isinstance(systems, list)


def test_find_repo_root_detects_git_directory(tmp_path: Path) -> None:
    nested = tmp_path / "nested" / "project"
    nested.mkdir(parents=True)
    (tmp_path / ".git").mkdir()
    assert find_repo_root(nested) == tmp_path


def test_find_repo_root_falls_back_to_start_when_no_git(tmp_path: Path) -> None:
    nested = tmp_path / "only" / "here"
    nested.mkdir(parents=True)
    assert find_repo_root(nested) == nested
