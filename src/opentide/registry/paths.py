"""Resolve workspace and package paths from merged configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.core.root import get_data_root
from opentide.package.paths import recomposition_platforms_root
from opentide.registry.discovery import client_configurations_dir, discover_workspace, opentide_dir


def workspace_config(configs: dict[str, Any]) -> dict[str, Any]:
    """Return paths config (``paths.toml``), falling back to legacy ``global.toml``."""
    if "paths" in configs:
        return configs["paths"]
    if "global" in configs:
        return configs["global"]
    raise KeyError("Bundled paths.toml or global.toml missing from configurations")


def _rel(base: Path, value: str) -> Path:
    return (base / value).resolve()


def _schema_templates_rel(
    paths_section: dict[str, Any],
    *,
    tide_legacy: dict[str, Any],
    framework_legacy: dict[str, Any],
    opentide_section: dict[str, Any],
    key: str,
    default: str,
) -> str:
    if opentide_section.get(key):
        return str(opentide_section[key])
    if framework_legacy.get(key):
        return str(framework_legacy[key])
    if tide_legacy.get("json_schemas" if key == "schemas" else "templates"):
        legacy_key = "json_schemas" if key == "schemas" else "templates"
        return str(tide_legacy[legacy_key])
    return default


def resolve_workspace_paths(
    configs: dict[str, Any] | None = None,
    *,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Resolve absolute paths for workspace + bundled package data."""
    if configs is None:
        from opentide.core.files import resolve_configurations

        configs = resolve_configurations()

    cfg = workspace_config(configs)
    base = workspace or discover_workspace()
    data_root = get_data_root()
    ot = opentide_dir(base)

    paths_section = cfg.get("paths", {})
    objects = paths_section.get("objects") or paths_section.get("tide", {})
    opentide_paths = paths_section.get("opentide", {})
    framework_legacy = paths_section.get("framework", {})
    exports = paths_section.get("exports", {})
    docs = paths_section.get("docs", {})
    core_legacy = paths_section.get("core", {})
    tide_legacy = paths_section.get("tide", {})

    if not objects and tide_legacy:
        objects = tide_legacy

    resolved: dict[str, Any] = {"_workspace_root": base, "opentide": ot}

    for key in ("threat", "objective", "rule"):
        rel = objects.get(key)
        if rel:
            resolved[key] = _rel(base, rel)

    default_schemas = ".opentide/schemas/"
    default_templates = ".opentide/templates/"
    schemas_rel = _schema_templates_rel(
        paths_section,
        tide_legacy=tide_legacy,
        framework_legacy=framework_legacy,
        opentide_section=opentide_paths,
        key="schemas",
        default=default_schemas,
    )
    templates_rel = _schema_templates_rel(
        paths_section,
        tide_legacy=tide_legacy,
        framework_legacy=framework_legacy,
        opentide_section=opentide_paths,
        key="templates",
        default=default_templates,
    )
    exports_rel = exports.get("root") or tide_legacy.get("exports", ".opentide/exports/")
    if not str(exports_rel).endswith("/"):
        exports_rel = f"{exports_rel}/"

    resolved["json_schemas"] = _rel(base, schemas_rel)
    resolved["templates"] = _rel(base, templates_rel)
    resolved["exports"] = _rel(base, exports_rel)
    resolved["inflight"] = ot / "inflight"

    resolved["docs_folder"] = _rel(base, docs.get("root", core_legacy.get("docs_folder", "docs/")))
    resolved["rules_docs_folder"] = _rel(
        base, docs.get("rules", core_legacy.get("rules_docs_folder", "docs/rules/"))
    )
    resolved["objectives_docs_folder"] = _rel(
        base, docs.get("objectives", core_legacy.get("objectives_docs_folder", "docs/objectives/"))
    )
    resolved["threats_docs_folder"] = _rel(
        base, docs.get("threats", core_legacy.get("threats_docs_folder", "docs/threats/"))
    )

    snippet = objects.get("snippet_file") or tide_legacy.get(
        "snippet_file", ".vscode/model-templates.code-snippets"
    )
    resolved["snippet_file"] = _rel(base, snippet)
    resolved["custom_configurations"] = client_configurations_dir(base)

    resolved["vocabularies"] = data_root / "vocabulary"
    resolved["resources"] = data_root / "external"
    resolved["log_sources"] = data_root / "log_sources"
    resolved["platform_configs"] = data_root / "configurations" / "platforms"
    resolved["platform_templates"] = recomposition_platforms_root()
    resolved["configurations"] = data_root / "configurations"

    artifacts = cfg.get("artifacts", {})
    resolved["_artifacts"] = {
        "schemas": artifacts.get("schemas") or cfg.get("json_schemas", {}),
        "templates": artifacts.get("templates") or cfg.get("templates", {}),
        "exports": artifacts.get("exports") or cfg.get("exports", {}),
    }

    return resolved


def legacy_path_aliases(paths: dict[str, Any]) -> dict[str, Any]:
    """Nested path dict expected by legacy registry accessors."""
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
