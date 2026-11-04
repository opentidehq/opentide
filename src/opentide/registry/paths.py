"""Resolve workspace and package paths from merged configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.core.root import get_data_root
from opentide.package.paths import platform_templates_root
from opentide.registry.discovery import client_configurations_dir, discover_workspace, opentide_dir


def workspace_config(configs: dict[str, Any]) -> dict[str, Any]:
    """Return the merged ``paths.toml`` document."""
    if "paths" in configs:
        return configs["paths"]
    raise KeyError("Bundled paths.toml missing from configurations")


def validate_paths_configuration(configs: dict[str, Any]) -> None:
    """Validate merged ``paths.toml`` against `PathsConfiguration`."""
    from opentide.models.configuration.loading import validate_configuration
    from opentide.models.configuration.paths import PathsConfiguration

    document = configs.get("paths")
    if isinstance(document, dict):
        validate_configuration(PathsConfiguration, document, file_key="paths.toml")


def _rel(base: Path, value: str) -> Path:
    return (base / value).resolve()


def resolve_workspace_paths(
    configs: dict[str, Any] | None = None,
    *,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Resolve absolute paths for workspace + bundled package data."""
    if configs is None:
        from opentide.core.files import resolve_configurations

        configs = resolve_configurations()

    validate_paths_configuration(configs)
    cfg = workspace_config(configs)
    base = workspace or discover_workspace()
    data_root = get_data_root()
    ot = opentide_dir(base)

    paths_section = cfg.get("paths", {})
    objects = paths_section.get("objects", {})
    opentide_paths = paths_section.get("opentide", {})
    exports = paths_section.get("exports", {})
    docs = paths_section.get("docs", {})

    resolved: dict[str, Any] = {"_workspace_root": base, "opentide": ot}

    for key in ("threat", "objective", "rule"):
        rel = objects.get(key)
        if rel:
            resolved[key] = _rel(base, rel)

    exports_rel = exports.get("root") or ".opentide/exports/"
    if not str(exports_rel).endswith("/"):
        exports_rel = f"{exports_rel}/"

    resolved["json_schemas"] = _rel(base, opentide_paths.get("schemas") or ".opentide/schemas/")
    resolved["templates"] = _rel(base, opentide_paths.get("templates") or ".opentide/templates/")
    resolved["exports"] = _rel(base, exports_rel)
    resolved["inflight"] = ot / "inflight"

    resolved["docs_folder"] = _rel(base, docs.get("root", "docs/"))
    resolved["rules_docs_folder"] = _rel(base, docs.get("rules", "docs/rules/"))
    resolved["objectives_docs_folder"] = _rel(base, docs.get("objectives", "docs/objectives/"))
    resolved["threats_docs_folder"] = _rel(base, docs.get("threats", "docs/threats/"))

    snippet = objects.get("snippet_file") or ".vscode/model-templates.code-snippets"
    resolved["snippet_file"] = _rel(base, snippet)
    resolved["custom_configurations"] = client_configurations_dir(base)

    resolved["vocabularies"] = data_root / "vocabulary"
    resolved["resources"] = data_root / "external"
    resolved["log_sources"] = data_root / "log_sources"
    resolved["platform_configs"] = data_root / "configurations" / "platforms"
    resolved["platform_templates"] = platform_templates_root()
    resolved["configurations"] = data_root / "configurations"

    artifacts = cfg.get("artifacts", {})
    resolved["_artifacts"] = {
        "schemas": artifacts.get("schemas", {}),
        "templates": artifacts.get("templates", {}),
        "exports": artifacts.get("exports", {}),
    }

    return resolved


def legacy_path_aliases(paths: dict[str, Any]) -> dict[str, Any]:
    """Nested path dict the registry accessors read (``Paths.Tide``, ``Paths.Core``)."""
    tide_keys = (
        "threat",
        "objective",
        "rule",
        "json_schemas",
        "templates",
        "exports",
        "snippet_file",
    )
    tide = {k: paths[k] for k in tide_keys if k in paths}
    tide["custom_configurations"] = paths.get(
        "custom_configurations",
        paths["opentide"] / "configurations",
    )
    core = {
        "vocabularies": paths["vocabularies"],
        "resources": paths["resources"],
        "log_sources": paths["log_sources"],
        "platform_configs": paths["platform_configs"],
        "platform_templates": paths["platform_templates"],
        "docs_folder": paths["docs_folder"],
        "rules_docs_folder": paths["rules_docs_folder"],
        "objectives_docs_folder": paths["objectives_docs_folder"],
        "threats_docs_folder": paths["threats_docs_folder"],
    }
    flat = dict(paths)
    flat["tide"] = tide
    flat["core"] = core
    flat["raw"] = {
        "tide": {k: str(v) for k, v in tide.items()},
        "core": {k: str(v) for k, v in core.items()},
    }
    return flat
