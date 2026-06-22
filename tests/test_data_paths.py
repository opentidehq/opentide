"""Phase 5 data path resolution tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.core.files import resolve_configurations, resolve_paths
from opentide.core.root import get_data_root, get_repo_root
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
    repo = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    configs = resolve_configurations()
    systems = configs.get("systems", {})
    assert "sentinel" in systems
    assert systems["sentinel"]["platform"]["identifier"] == "sentinel"


def test_resolve_paths_uses_bundled_vocabulary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    paths = resolve_paths()
    assert paths["vocabularies"] == get_data_root() / "vocabulary"
    assert paths["resources"] == get_data_root() / "external"
    assert paths["platform_configs"] == get_data_root() / "configurations" / "platforms"


def test_enabled_systems_reads_merged_config(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    systems = enabled_systems()
    assert isinstance(systems, list)
