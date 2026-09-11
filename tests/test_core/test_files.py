"""Unit tests for opentide.core.files helpers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from opentide.core.files import (
    IndentFullDumper,
    OrderedYAMLDumper,
    _bundled_platform_configs,
    _fetch_configs,
    resolve_configurations,
    resolve_paths,
    safe_file_name,
)
from opentide.core.root import get_repo_root


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hello/world", "helloworld"),
        ("safe-name", "safe-name"),
        ('bad<>:"|?*', "bad"),
    ],
)
def test_safe_file_name(raw: str, expected: str) -> None:
    assert safe_file_name(raw) == expected


def test_indent_full_dumper_preserves_nested_structure() -> None:
    payload = {"outer": {"inner": [1, 2]}}
    dumped = yaml.dump(payload, Dumper=IndentFullDumper, default_flow_style=False)
    loaded = yaml.safe_load(dumped)
    assert loaded == payload


def test_ordered_yaml_dumper_is_indent_full_subclass() -> None:
    assert issubclass(OrderedYAMLDumper, IndentFullDumper)
    payload = {"z": 1, "a": {"b": 2}}
    dumped = yaml.dump(payload, Dumper=OrderedYAMLDumper, default_flow_style=False)
    assert dumped.startswith("z:") or "z:" in dumped


def test_fetch_configs_reads_top_level_and_nested_toml(tmp_path: Path) -> None:
    (tmp_path / "global.toml").write_text('title = "global"\n', encoding="utf-8")
    systems = tmp_path / "systems"
    systems.mkdir()
    (systems / "sentinel.toml").write_text(
        '[platform]\nidentifier = "sentinel"\n',
        encoding="utf-8",
    )
    configs = _fetch_configs(tmp_path)
    assert configs["global"]["title"] == "global"
    assert configs["systems"]["sentinel"]["platform"]["identifier"] == "sentinel"


def test_fetch_configs_uses_tide_identifier_fallback(tmp_path: Path) -> None:
    systems = tmp_path / "systems"
    systems.mkdir()
    (systems / "legacy.toml").write_text('[tide]\nidentifier = "legacy"\n', encoding="utf-8")
    configs = _fetch_configs(tmp_path)
    assert configs["systems"]["legacy"]["tide"]["identifier"] == "legacy"


def test_fetch_configs_returns_empty_for_missing_directory(tmp_path: Path) -> None:
    assert _fetch_configs(tmp_path / "missing") == {}


def test_fetch_configs_skips_non_file_entries_in_nested_dir(tmp_path: Path) -> None:
    systems = tmp_path / "systems"
    systems.mkdir()
    (systems / "nested-dir").mkdir()
    (systems / "sentinel.toml").write_text(
        '[platform]\nidentifier = "sentinel"\n',
        encoding="utf-8",
    )
    configs = _fetch_configs(tmp_path)
    assert configs["systems"]["sentinel"]["platform"]["identifier"] == "sentinel"


def test_fetch_configs_ignores_pycache_with_non_utf8_bytecode(tmp_path: Path) -> None:
    """Top-level ``__pycache__`` must not be read as TOML (PR #150).

    Bundled config packages ship ``__init__.py``. pip compileall writes
    ``__pycache__/*.pyc`` whose 3.13+ magic (``f3 0d 0d 0a``) is not UTF-8.
    """
    (tmp_path / "global.toml").write_text('title = "global"\n', encoding="utf-8")
    pycache = tmp_path / "__pycache__"
    pycache.mkdir()
    (pycache / "__init__.cpython-313.pyc").write_bytes(b"\xf3\r\r\n\x00\x00\x00\x00")

    configs = _fetch_configs(tmp_path)

    assert configs["global"]["title"] == "global"
    assert "__pycache__" not in configs


def test_fetch_configs_ignores_non_toml_files_in_nested_dir(tmp_path: Path) -> None:
    """Nested config dirs may contain ``__init__.py`` / README that are not TOML."""
    platforms = tmp_path / "platforms"
    platforms.mkdir()
    (platforms / "__init__.py").write_text("\n", encoding="utf-8")
    (platforms / "README.md").write_text("# not toml\n", encoding="utf-8")
    (platforms / "sentinel.toml").write_text(
        '[platform]\nidentifier = "sentinel"\n',
        encoding="utf-8",
    )

    configs = _fetch_configs(tmp_path)

    assert configs["platforms"]["sentinel"]["platform"]["identifier"] == "sentinel"
    assert "__init__" not in configs["platforms"]
    assert "README" not in configs["platforms"]


def test_resolve_configurations_survives_compiled_bytecode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import compileall
    import shutil

    from opentide.core.root import get_data_root

    dest = tmp_path / "data"
    shutil.copytree(get_data_root(), dest)
    compileall.compile_dir(str(dest / "configurations"), quiet=1, force=True)
    assert any((dest / "configurations" / "__pycache__").glob("*.pyc"))

    monkeypatch.setenv("OPENTIDE_DATA_ROOT", str(dest))
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    get_data_root.cache_clear()
    try:
        configs = resolve_configurations()
    finally:
        get_data_root.cache_clear()
    assert "global" in configs
    assert configs.get("platforms") or configs.get("systems")


def test_bundled_platform_configs_returns_empty_when_data_root_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "opentide.core.files.get_data_root",
        lambda: Path("/definitely-missing-data-root"),
    )
    assert _bundled_platform_configs() == {}


def test_safe_file_name_unsafe_mode_honours_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert safe_file_name("a/b", safe_mode=False) == "ab"
    monkeypatch.setattr(sys, "platform", "win32")
    assert safe_file_name("a<b", safe_mode=False) == "ab"


def test_resolve_configurations_merges_parent_opentide_configs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "client" / "project"
    workspace.mkdir(parents=True)
    parent_configs = tmp_path / "client" / ".opentide" / "configurations"
    parent_configs.mkdir(parents=True)
    (parent_configs / "overlay.toml").write_text('marker = "parent"\n', encoding="utf-8")

    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(workspace))
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    get_repo_root.cache_clear()

    configs = resolve_configurations()
    assert configs["overlay"]["marker"] == "parent"


def test_resolve_paths_supports_separate_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    get_repo_root.cache_clear()
    tide_paths, core_paths = resolve_paths(separate=True)
    assert isinstance(tide_paths, dict)
    assert isinstance(core_paths, dict)
    assert tide_paths
