"""Configuration merge and path resolution for opentide instances."""

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

from opentide.core.errors import ConfigFileError, RetiredConfigurationError
from opentide.core.root import get_data_root, get_repo_root
from opentide.registry.discovery import client_configurations_dir, discover_workspace


def deep_merge(source: dict, merge: dict) -> None:
    """Merge *merge* into *source*: tables merge, scalars and arrays replace."""
    for key, value in merge.items():
        if (
            key in source
            and isinstance(source[key], MutableMapping)
            and isinstance(value, MutableMapping)
        ):
            deep_merge(source[key], value)  # type: ignore[arg-type]
        else:
            source[key] = value


def _load_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        # A typo in the user's own file, not a bug: say where it is.
        raise ConfigFileError.from_toml(path, exc) from exc


# ``sharing.toml`` merges arrays of tables by block name. ``deep_merge``
# replaces lists wholesale, so the sharing loader owns that file.
_SKIPPED_CONFIG_FILES = frozenset({"sharing.toml"})


def _is_skipped_config_dir(name: str) -> bool:
    """Skip hidden and dunder names (``__pycache__``, ``.DS_Store``, …)."""
    return name.startswith((".", "__"))


def _load_nested_configs(directory: Path) -> dict[str, dict]:
    """Load ``*.toml`` files from one configuration subdirectory."""
    nested: dict[str, dict] = {}
    for toml_path in sorted(directory.glob("*.toml")):
        if not toml_path.is_file():
            continue
        nested[toml_path.stem] = _load_toml(toml_path)
    return nested


def _fetch_configs(configuration_path: Path) -> dict[str, dict]:
    config_index: dict[str, dict] = {}
    if not configuration_path.is_dir():
        return config_index

    for entry_path in sorted(configuration_path.iterdir(), key=lambda path: path.name):
        if entry_path.is_file() and entry_path.name.endswith(".toml"):
            if entry_path.name in _SKIPPED_CONFIG_FILES:
                continue
            config_index[entry_path.name.removesuffix(".toml")] = _load_toml(entry_path)
            continue
        if not entry_path.is_dir() or _is_skipped_config_dir(entry_path.name):
            continue
        config_index[entry_path.name] = _load_nested_configs(entry_path)

    return config_index


def _bundled_platform_configs() -> dict[str, dict]:
    platforms_dir = get_data_root() / "configurations" / "platforms"
    systems: dict[str, dict] = {}
    if not platforms_dir.is_dir():
        return systems

    for toml_path in sorted(platforms_dir.glob("*.toml")):
        systems[toml_path.stem] = _load_toml(toml_path)
    return systems


def resolve_configurations(workspace: Path | None = None) -> dict[str, dict]:
    """Merge bundled, optional workspace, and parent-instance configuration TOMLs.

    *workspace* defaults to the discovered detection workspace.
    """
    data_root = get_data_root()
    unified = _fetch_configs(data_root / "configurations")
    if "paths" not in unified:
        raise KeyError("Bundled paths.toml missing from opentide.data.configurations")

    unified.setdefault("platforms", {})
    bundled = _bundled_platform_configs()
    if bundled:
        deep_merge(unified["platforms"], bundled)
    unified.setdefault("systems", unified["platforms"])

    workspace = workspace or discover_workspace()
    client_configs = client_configurations_dir(workspace)
    if client_configs.is_dir():
        reject_retired_configurations(client_configs)
        deep_merge(unified, _fetch_configs(client_configs))

    root = get_repo_root()
    workspace_env = os.environ.get("OPENTIDE_TIDE_WORKSPACE")
    if workspace_env:
        fixture_configs = root / "tests/fixtures/generation/configurations"
        if fixture_configs.is_dir():
            deep_merge(unified, _fetch_configs(fixture_configs))

    parent_configs = workspace.parent / ".opentide" / "configurations"
    if parent_configs.is_dir() and parent_configs != client_configs and not workspace_env:
        reject_retired_configurations(parent_configs)
        deep_merge(unified, _fetch_configs(parent_configs))

    _reject_retired_proxy(unified)
    return unified


#: Entries of a configuration folder that opentide does not read, and what replaces each.
RETIRED_CONFIGURATIONS: dict[str, str] = {
    "global.toml": "workspace paths and artifact names are set in paths.toml",
    "schema.toml": (
        "template defaults are not configurable, and vocabularies are not extended locally"
    ),
    "systems": "platform files live in platforms/<platform>.toml",
}


def reject_retired_configurations(directory: Path) -> None:
    """Refuse a file or folder under *directory* that opentide does not read.

    A retired file was loaded and then ignored, so a workspace believed it was
    configured by it. Raise :class:`RetiredConfigurationError` naming the
    replacement instead.
    """
    for name, replacement in RETIRED_CONFIGURATIONS.items():
        entry = directory / name
        if entry.exists():
            raise RetiredConfigurationError(
                entry, f"{name} is not read by opentide: {replacement}."
            )


def _reject_retired_proxy(unified: dict[str, dict]) -> None:
    """A leftover proxy key names ``opentide --proxy`` instead of applying it."""
    message = "Pass the proxy URL with `opentide --proxy http://[user:pass@]host:port`."
    deployment = unified.get("deployment")
    if isinstance(deployment, dict) and "proxy" in deployment:
        raise ValueError(f"deployment.toml [proxy] is retired. {message}")
    documentation = unified.get("documentation")
    if isinstance(documentation, dict):
        cve = documentation.get("cve")
        if isinstance(cve, dict) and "proxy" in cve:
            raise ValueError(f"[cve].proxy is retired. {message}")


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
