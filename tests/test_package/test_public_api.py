"""Public package API: imports, version, bundled data, entry points."""

from __future__ import annotations

import importlib
from importlib.metadata import entry_points
from importlib.resources import files
from pathlib import Path

import pytest

from opentide import OpenTide, __version__
from opentide.core.root import get_data_root, get_repo_root
from opentide.schemas.store import (
    bundled_data_exists,
    external_root,
    platform_configs_root,
    vocabulary_root,
)


def test_import_opentide() -> None:
    opentide = importlib.import_module("opentide")
    assert opentide.__version__


def test_import_opentide_public_api() -> None:
    assert OpenTide is not None
    assert __version__


def test_import_opentide_core_registry() -> None:
    from opentide.core.registry import OpenTide as RegistryOpenTide

    assert RegistryOpenTide is not None


def test_bundled_data_via_importlib_resources() -> None:
    data_path = Path(str(files("opentide.data")))
    assert data_path.is_dir()
    platforms = list((data_path / "configurations" / "platforms").glob("*.toml"))
    assert len(platforms) == 7


def test_get_data_root_default() -> None:
    root = get_data_root()
    assert root.is_dir()
    assert (root / "configurations" / "platforms" / "sentinel.toml").is_file()


def test_get_data_root_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    custom = tmp_path / "custom-data"
    custom.mkdir()
    monkeypatch.setenv("OPENTIDE_DATA_ROOT", str(custom))
    get_data_root.cache_clear()
    try:
        assert get_data_root() == custom
    finally:
        get_data_root.cache_clear()


def test_get_repo_root_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))
    get_repo_root.cache_clear()
    try:
        assert get_repo_root() == tmp_path
    finally:
        get_repo_root.cache_clear()


def test_schema_store_paths() -> None:
    assert vocabulary_root().name == "vocabulary"
    assert external_root().name == "external"
    assert platform_configs_root().name == "platforms"
    assert bundled_data_exists()


def test_platform_entry_points_registered() -> None:
    names = {ep.name for ep in entry_points(group="opentide.platforms")}
    expected = {
        "sentinel",
        "splunk",
        "crowdstrike",
        "carbon_black_cloud",
        "defender_for_endpoint",
        "sentinel_one",
        "harfanglab",
    }
    assert expected <= names


def test_package_import_has_no_auto_load_side_effects() -> None:
    from opentide.core.registry import OpenTide as RegistryOpenTide

    assert not RegistryOpenTide.is_initialised
    opentide = importlib.import_module("opentide")
    assert hasattr(opentide, "__version__")
    assert not RegistryOpenTide.is_initialised
