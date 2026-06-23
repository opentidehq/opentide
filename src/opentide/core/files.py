"""Configuration merge and path resolution for OpenTide instances."""

from __future__ import annotations

import os
import sys
from collections.abc import MutableMapping
from pathlib import Path
from typing import Literal, overload

import toml
import yaml

from opentide.core.root import get_data_root, get_repo_root


def _deep_merge(source: dict, merge: dict) -> None:
    for key, value in merge.items():
        if (
            key in source
            and isinstance(source[key], MutableMapping)
            and isinstance(value, MutableMapping)
        ):
            _deep_merge(source[key], value)  # type: ignore[arg-type]
        else:
            source[key] = value


def _load_toml(path: Path) -> dict:
    return toml.loads(path.read_text(encoding="utf-8"))


def _fetch_configs(configuration_path: Path) -> dict[str, dict]:
    config_index: dict[str, dict] = {}
    if not configuration_path.is_dir():
        return config_index

    for entry in os.listdir(configuration_path):
        entry_path = configuration_path / entry
        if entry_path.is_file() and entry.endswith(".toml"):
            config_index[entry.removesuffix(".toml")] = _load_toml(entry_path)
        elif entry_path.is_dir():
            config_index[entry] = {}
            for config_name in os.listdir(entry_path):
                config_path = entry_path / config_name
                if not config_path.is_file():
                    continue
                configuration = _load_toml(config_path)
                key = configuration.get("tide", {}).get("identifier") or config_name.removesuffix(
                    ".toml"
                )
                config_index[entry][key] = configuration

    return config_index


def _bundled_platform_configs() -> dict[str, dict]:
    """Load default platform TOMLs shipped inside ``opentide.data``."""
    platforms_dir = get_data_root() / "configurations" / "platforms"
    systems: dict[str, dict] = {}
    if not platforms_dir.is_dir():
        return systems

    for toml_path in sorted(platforms_dir.glob("*.toml")):
        configuration = _load_toml(toml_path)
        key = (
            configuration.get("tide", {}).get("identifier")
            or configuration.get("platform", {}).get("identifier")
            or toml_path.stem
        )
        systems[key] = configuration
    return systems


def resolve_configurations() -> dict[str, dict]:
    """Merge bundled, optional repo, and parent-instance configuration TOMLs."""
    data_root = get_data_root()
    unified = _fetch_configs(data_root / "configurations")
    if "global" not in unified:
        raise KeyError("Bundled global.toml missing from opentide.data.configurations")

    if "systems" not in unified:
        unified["systems"] = {}
    bundled = _bundled_platform_configs()
    if bundled:
        _deep_merge(unified["systems"], bundled)

    root = get_repo_root()
    repo_configs = root / "Configurations"
    if repo_configs.is_dir():
        _deep_merge(unified, _fetch_configs(repo_configs))

    parent_configs = root.parent / "Configurations"
    if parent_configs.is_dir() and parent_configs != repo_configs:
        _deep_merge(unified, _fetch_configs(parent_configs))

    return unified


@overload
def resolve_paths(separate: Literal[True]) -> tuple[dict[str, Path], dict[str, Path]]: ...


@overload
def resolve_paths(separate: Literal[False]) -> dict[str, Path]: ...


@overload
def resolve_paths() -> dict[str, Path]: ...


def resolve_paths(separate: bool = False):
    """Resolve absolute Tide and core paths from merged configuration."""
    root = get_repo_root()
    configs = resolve_configurations()
    core_config = configs["global"]

    workspace = os.environ.get("OPENTIDE_TIDE_WORKSPACE")
    tide_base = Path(workspace) if workspace else root.parent
    paths = {k: (tide_base / path) for k, path in core_config["paths"]["tide"].items()}

    data_root = get_data_root()
    core_paths = {k: (root / path) for k, path in core_config["paths"]["core"].items()}
    core_paths["vocabularies"] = data_root / "vocabulary"
    core_paths["resources"] = data_root / "external"
    core_paths["platform_configs"] = data_root / "configurations" / "platforms"
    core_paths["log_sources"] = data_root / "log_sources"

    if separate:
        return paths, core_paths
    return paths | core_paths


def safe_file_name(string: str, safe_mode: bool = True) -> str:
    """Sanitise a human-readable string for cross-platform file names."""
    cleaned: list[str] = []
    forbidden_windows = {">", "<", ":", '"', "\\", "/", "|", "?", "*"}
    forbidden_linux = {"/"}
    forbidden = forbidden_windows | forbidden_linux if safe_mode else set()

    if not safe_mode:
        platform = sys.platform
        if platform.startswith("linux"):
            forbidden = forbidden_linux
        elif platform.startswith("win32"):
            forbidden = forbidden_windows

    for char in string:
        if char not in forbidden:
            cleaned.append(char)
    return "".join(cleaned)


class IndentFullDumper(yaml.Dumper):
    def increase_indent(self, flow: bool = False, indentless: bool = False):
        return super().increase_indent(flow, False)


class OrderedYAMLDumper(IndentFullDumper):
    """YAML dumper preserving key order with full indentation."""
