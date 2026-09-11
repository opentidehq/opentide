"""Configuration merge and path resolution for OpenTide instances."""

from __future__ import annotations

import os
import sys
from collections.abc import MutableMapping
from pathlib import Path
from typing import Literal, overload

import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from opentide.core.root import get_data_root, get_repo_root
from opentide.registry.discovery import client_configurations_dir, discover_workspace


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
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _fetch_configs(configuration_path: Path) -> dict[str, dict]:
    config_index: dict[str, dict] = {}
    if not configuration_path.is_dir():
        return config_index

    for entry in os.listdir(configuration_path):
        # Skip hidden/dunder entries (e.g. __pycache__, .DS_Store): they are
        # never config namespaces and their contents (bytecode, metadata) are
        # not valid TOML.
        if entry.startswith((".", "__")):
            continue
        entry_path = configuration_path / entry
        if entry_path.is_file() and entry.endswith(".toml"):
            config_index[entry.removesuffix(".toml")] = _load_toml(entry_path)
        elif entry_path.is_dir():
            config_index[entry] = {}
            for config_name in os.listdir(entry_path):
                config_path = entry_path / config_name
                if not config_path.is_file() or not config_name.endswith(".toml"):
                    continue
                configuration = _load_toml(config_path)
                key = (
                    configuration.get("platform", {}).get("identifier")
                    or configuration.get("tide", {}).get("identifier")
                    or config_name.removesuffix(".toml")
                )
                config_index[entry][key] = configuration

    return config_index


def _bundled_platform_configs() -> dict[str, dict]:
    platforms_dir = get_data_root() / "configurations" / "platforms"
    systems: dict[str, dict] = {}
    if not platforms_dir.is_dir():
        return systems

    for toml_path in sorted(platforms_dir.glob("*.toml")):
        configuration = _load_toml(toml_path)
        key = (
            configuration.get("platform", {}).get("identifier")
            or configuration.get("tide", {}).get("identifier")
            or toml_path.stem
        )
        systems[key] = configuration
    return systems


def resolve_configurations() -> dict[str, dict]:
    """Merge bundled, optional workspace, and parent-instance configuration TOMLs."""
    data_root = get_data_root()
    unified = _fetch_configs(data_root / "configurations")
    if "paths" not in unified and "global" not in unified:
        raise KeyError(
            "Bundled paths.toml or global.toml missing from opentide.data.configurations"
        )

    if "paths" in unified and "global" not in unified:
        unified["global"] = unified["paths"]

    if "platforms" not in unified:
        unified["platforms"] = unified.get("systems", {})
    bundled = _bundled_platform_configs()
    if bundled:
        _deep_merge(unified["platforms"], bundled)
    unified.setdefault("systems", unified["platforms"])

    workspace = discover_workspace()
    client_configs = client_configurations_dir(workspace)
    if client_configs.is_dir():
        _deep_merge(unified, _fetch_configs(client_configs))

    root = get_repo_root()
    workspace_env = os.environ.get("OPENTIDE_TIDE_WORKSPACE")
    if workspace_env:
        fixture_configs = root / "tests/fixtures/generation/configurations"
        if fixture_configs.is_dir():
            _deep_merge(unified, _fetch_configs(fixture_configs))

    parent_configs = workspace.parent / ".opentide" / "configurations"
    if (
        parent_configs.is_dir()
        and parent_configs != client_configs
        and not workspace_env
        and parent_configs != client_configs
    ):
        _deep_merge(unified, _fetch_configs(parent_configs))

    return unified


@overload
def resolve_paths(separate: Literal[True]) -> tuple[dict[str, Path], dict[str, Path]]:
    pass


@overload
def resolve_paths(separate: Literal[False]) -> dict[str, Path]:
    pass


@overload
def resolve_paths() -> dict[str, Path]:
    pass


def resolve_paths(separate: bool = False):
    """Resolve absolute workspace paths from merged configuration."""
    from opentide.registry.paths import legacy_path_aliases, resolve_workspace_paths

    configs = resolve_configurations()
    paths = resolve_workspace_paths(configs)
    aliases = legacy_path_aliases(paths)
    tide_paths = aliases["tide"]
    core_paths = aliases["core"]
    if separate:
        return tide_paths, core_paths
    flat = dict(paths)
    flat.update(tide_paths)
    flat.update(core_paths)
    return flat


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
