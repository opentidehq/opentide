"""Deprecated interim VS Code setup.

Superseded by the OpenTide VS Code extension (bundled language server and templates).
"""

from __future__ import annotations

import importlib
import json
import sys
import warnings
from pathlib import Path

import structlog

from opentide.cli.services.setup.templates import load_yaml_schema_fragment
from opentide.core.files import resolve_configurations
from opentide.registry.discovery import OPENTIDE_DIR

logger = structlog.get_logger("opentide.cli.services.setup.vscode")

DEPRECATION_MESSAGE = (
    "opentide setup vscode is deprecated and will be removed when the OpenTide "
    "VS Code extension ships with a bundled language server and template actions."
)


def snippet_file_rel(*, workspace: Path | None = None) -> str:
    """Relative snippet path from merged configuration (matches ``opentide generate snippets``)."""
    from opentide.core.files import resolve_configurations
    from opentide.registry.discovery import discover_workspace
    from opentide.registry.paths import resolve_workspace_paths

    base = (workspace or discover_workspace()).resolve()
    paths = resolve_workspace_paths(resolve_configurations(), workspace=base)
    snippet = Path(paths["snippet_file"])
    try:
        return str(snippet.relative_to(base))
    except ValueError:
        return str(snippet)


RECOMMENDED_EXTENSIONS: tuple[str, ...] = ("redhat.vscode-yaml",)


def emit_vscode_deprecation() -> None:
    warnings.warn(DEPRECATION_MESSAGE, DeprecationWarning, stacklevel=3)
    logger.warning("vscode_setup_deprecated", detail=DEPRECATION_MESSAGE)


def build_yaml_schema_mappings(*, workspace: Path | None = None) -> dict[str, str]:
    """Build per-folder yaml.schemas mappings from bundled paths.toml.

    The Red Hat YAML extension cannot reliably narrow ``opentide.schema.json``
    (a oneOf/if-then router) against a single ``objects/**/*.yaml`` glob, which
    produces "Matches multiple schemas" and disables autocompletion. Map each
    core object family to its concrete schema with a recursive per-folder glob
    (``objects/threats/**/*.yaml``), matching ``Path.rglob("*.yaml")`` object
    discovery. Do not collapse families onto the router glob.
    """
    del workspace  # reserved for future workspace-relative schema URIs
    configs = resolve_configurations()
    cfg = configs.get("paths") or configs["global"]
    artifacts = cfg.get("artifacts", {})
    schema_map: dict[str, str] = dict(artifacts.get("schemas", cfg.get("json_schemas", {})))
    object_dirs = (cfg.get("paths") or {}).get("objects") or {}
    mappings: dict[str, str] = {}
    for object_type in ("threat", "objective", "rule"):
        schema_name = schema_map.get(object_type, f"{object_type}.1.0.schema.json")
        folder = str(object_dirs.get(object_type, f"objects/{object_type}s/"))
        glob = f"{folder.rstrip('/')}/**/*.yaml"
        mappings[f"{OPENTIDE_DIR}/schemas/{schema_name}"] = glob
    return mappings


def _router_schema_uri() -> str:
    configs = resolve_configurations()
    cfg = configs.get("paths") or configs["global"]
    artifacts = cfg.get("artifacts", {})
    schema_map: dict[str, str] = dict(artifacts.get("schemas", cfg.get("json_schemas", {})))
    return f"{OPENTIDE_DIR}/schemas/{schema_map.get('router', 'opentide.schema.json')}"


def write_vscode_settings(target: Path, *, merge: bool = True) -> str:
    """Write or merge .vscode/settings.json with OpenTide yaml.schemas."""
    vscode_dir = target / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    settings_path = vscode_dir / "settings.json"
    mappings = build_yaml_schema_mappings(workspace=target.resolve())
    if merge and settings_path.is_file():
        existing = json.loads(settings_path.read_text(encoding="utf-8"))
    else:
        existing = {}
    yaml_schemas = existing.get("yaml.schemas", {})
    if not isinstance(yaml_schemas, dict):
        yaml_schemas = {}
    yaml_schemas.pop(_router_schema_uri(), None)
    yaml_schemas.update(mappings)
    existing["yaml.schemas"] = yaml_schemas
    settings_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return ".vscode/settings.json"


def write_vscode_extensions(target: Path, *, merge: bool = True) -> str:
    """Write or merge .vscode/extensions.json recommending the YAML extension."""
    vscode_dir = target / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    extensions_path = vscode_dir / "extensions.json"
    if merge and extensions_path.is_file():
        existing = json.loads(extensions_path.read_text(encoding="utf-8"))
    else:
        existing = {}
    recommendations = existing.get("recommendations", [])
    if not isinstance(recommendations, list):
        recommendations = []
    for extension_id in RECOMMENDED_EXTENSIONS:
        if extension_id not in recommendations:
            recommendations.append(extension_id)
    existing["recommendations"] = recommendations
    extensions_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return ".vscode/extensions.json"


def _templates_ready(target: Path) -> bool:
    templates_dir = target / OPENTIDE_DIR / "templates"
    if not templates_dir.is_dir():
        return False
    return any(templates_dir.glob("*.yaml")) or any(templates_dir.glob("*.yml"))


def run_vscode_snippets(target: Path) -> str | None:
    """Generate VS Code snippets under ``target``; returns relative path or None."""
    from opentide.cli.services.generation import workspace_repo_env

    resolved = target.resolve()
    if not _templates_ready(resolved):
        logger.warning(
            "vscode_snippets_skipped",
            detail=f"No templates in {OPENTIDE_DIR}/templates — run opentide generate first",
        )
        return None

    snippets_rel = snippet_file_rel(workspace=resolved)
    dest = resolved / snippets_rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    vscode_snippets = None
    try:
        with workspace_repo_env(resolved):
            vscode_snippets = importlib.import_module("opentide.generation.vscode_snippets")
            vscode_snippets.SNIPPETS_PATH = snippets_rel
            vscode_snippets.run()
    except FileNotFoundError as exc:
        logger.warning("vscode_snippets_skipped", detail=str(exc))
        return None
    finally:
        module = vscode_snippets or sys.modules.get("opentide.generation.vscode_snippets")
        if module is not None and hasattr(module, "SNIPPETS_PATH"):
            module.SNIPPETS_PATH = None

    return snippets_rel if dest.is_file() else None


def run_vscode_settings(target: Path, *, merge: bool = True) -> dict[str, object]:
    files = [
        write_vscode_settings(target, merge=merge),
        write_vscode_extensions(target, merge=merge),
    ]
    return {"message": "VS Code settings generated", "files": files}


def run_vscode_setup(
    target: Path,
    *,
    settings: bool = True,
    snippets: bool = True,
    generate: bool = True,
    merge: bool = True,
    warn_deprecated: bool = True,
) -> dict[str, object]:
    """Generate prerequisites, then write VS Code settings and/or snippets.

    Deprecation is emitted once at this boundary. Callers must not also call
    ``emit_vscode_deprecation``.
    """
    from opentide.cli.services.generation import run_generate_phases_for_workspace

    if warn_deprecated:
        emit_vscode_deprecation()

    generated: list[str] = []
    if generate:
        phases: list[str] = []
        if snippets:
            phases.append("templates")
        if settings:
            phases.append("schemas")
        if phases:
            generated = run_generate_phases_for_workspace(target, phases)

    files: list[str] = []
    if settings:
        files.append(write_vscode_settings(target, merge=merge))
        files.append(write_vscode_extensions(target, merge=merge))

    snippet_path: str | None = None
    if snippets:
        snippet_path = run_vscode_snippets(target)
        if snippet_path:
            files.append(snippet_path)

    payload: dict[str, object] = {
        "message": "VS Code setup complete (deprecated)",
        "files": files,
        "generated": generated,
        "deprecated": DEPRECATION_MESSAGE,
        "status": "completed",
    }
    if snippets and snippet_path is None:
        payload["status"] = "failed"
        payload["_exit_code"] = 1
        payload["message"] = (
            f"VS Code snippets were not generated (no templates in {OPENTIDE_DIR}/templates)"
        )
        logger.error(
            "vscode_snippets_missing",
            detail=payload["message"],
        )
    return payload


def run_vscode_all(target: Path, *, merge: bool = True, generate: bool = True) -> dict[str, object]:
    return run_vscode_setup(target, merge=merge, generate=generate)


def validate_schema_fragment_matches_global() -> None:
    """Ensure bundled fragment stays aligned with paths.toml (tests)."""
    fragment = load_yaml_schema_fragment()
    assert fragment.get("yaml.schemas") == build_yaml_schema_mappings()
