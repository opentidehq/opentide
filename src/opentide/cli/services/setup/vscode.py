"""Deprecated interim VS Code setup.

Superseded by the opentide VS Code extension (bundled language server and templates).
"""

from __future__ import annotations

import importlib
import json
import re
import sys
import warnings
from pathlib import Path, PurePosixPath
from typing import Any

import structlog

from opentide.cli.services.setup.templates import load_yaml_schema_fragment
from opentide.core.files import resolve_configurations
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.registry.discovery import OPENTIDE_DIR

logger = structlog.get_logger("opentide.cli.services.setup.vscode")

_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_jsonc(text: str) -> str:
    """Drop comments and trailing commas so VS Code JSONC settings parse."""
    out: list[str] = []
    index = 0
    length = len(text)
    in_string = False
    escape = False
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < length and text[index + 1] == "/":
            index += 2
            while index < length and text[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and index + 1 < length and text[index + 1] == "*":
            index += 2
            while index + 1 < length and not (text[index] == "*" and text[index + 1] == "/"):
                index += 1
            index = min(index + 2, length)
            continue
        out.append(char)
        index += 1
    return _TRAILING_COMMA.sub(r"\1", "".join(out))


def _load_jsonc(path: Path) -> Any:
    try:
        return json.loads(_strip_jsonc(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read {path}: {exc}") from exc


DEPRECATION_MESSAGE = (
    "opentide setup vscode is deprecated and will be removed when the opentide "
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


def _paths_config() -> dict[str, Any]:
    configs = resolve_configurations()
    return configs.get("paths") or configs["global"]


def _schema_artifacts(cfg: dict[str, Any]) -> dict[str, str]:
    artifacts = cfg.get("artifacts", {})
    return dict(artifacts.get("schemas", cfg.get("json_schemas", {})))


def _object_folders(cfg: dict[str, Any]) -> list[str]:
    """Configured object folders, workspace-relative and without trailing ``/``."""
    families = cfg.get("objects") or list(CORE_OBJECT_TYPES)
    object_dirs = (cfg.get("paths") or {}).get("objects") or {}
    return [str(object_dirs.get(family, f"objects/{family}s/")).rstrip("/") for family in families]


def _object_glob(folders: list[str]) -> str | list[str]:
    """One recursive glob over the common parent of every object folder.

    Matches ``Path.rglob("*.yaml")`` object discovery. When the folders share
    no parent, fall back to one recursive glob per folder.
    """
    parents = {PurePosixPath(folder).parent.as_posix() for folder in folders}
    if len(parents) == 1:
        parent = parents.pop()
        if parent not in ("", "."):
            return f"{parent}/**/*.yaml"
    return [f"{folder}/**/*.yaml" for folder in folders]


def _router_schema_uri(cfg: dict[str, Any] | None = None) -> str:
    schema_map = _schema_artifacts(cfg or _paths_config())
    return f"{OPENTIDE_DIR}/schemas/{schema_map.get('router', 'opentide.schema.json')}"


def build_yaml_schema_mappings(*, workspace: Path | None = None) -> dict[str, str | list[str]]:
    """Map every object file to the ``opentide.schema.json`` router.

    The router selects the revision schema from ``metadata.schema``, so
    revisions of one family (``rule::1.0`` and ``rule::1.1``) coexist in one
    folder. A per-folder mapping to a single revision schema cannot express that.
    """
    del workspace  # reserved for future workspace-relative schema URIs
    cfg = _paths_config()
    return {_router_schema_uri(cfg): _object_glob(_object_folders(cfg))}


def _is_stale_revision_mapping(
    schema: str, globs: object, *, families: list[str], folders: list[str]
) -> bool:
    """True for a per-folder revision mapping an earlier ``setup vscode`` wrote.

    Those mapped ``.opentide/schemas/<family>.<major>.<minor>.schema.json`` to
    ``<folder>/**/*.yaml`` (or ``<folder>/*.yaml``). Left in place they
    validate every object against one revision, alongside the router.
    """
    pattern = rf"{re.escape(OPENTIDE_DIR)}/schemas/(?:{'|'.join(map(re.escape, families))})"
    if not re.fullmatch(pattern + r"\.\d+\.\d+\.schema\.json", schema.removeprefix("./")):
        return False
    generated = {f"{folder}/{suffix}" for folder in folders for suffix in ("**/*.yaml", "*.yaml")}
    values = [globs] if isinstance(globs, str) else globs
    return (
        isinstance(values, list)
        and bool(values)
        and all(isinstance(value, str) and value in generated for value in values)
    )


def write_vscode_settings(target: Path, *, merge: bool = True) -> str:
    """Write or merge .vscode/settings.json with opentide yaml.schemas.

    Merging keeps unrelated settings and user mappings, and drops the
    per-folder revision mappings earlier releases generated.
    """
    vscode_dir = target / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    settings_path = vscode_dir / "settings.json"
    mappings = build_yaml_schema_mappings(workspace=target.resolve())
    existing = _load_jsonc(settings_path) if merge and settings_path.is_file() else {}
    yaml_schemas = existing.get("yaml.schemas", {})
    if not isinstance(yaml_schemas, dict):
        yaml_schemas = {}
    cfg = _paths_config()
    families = list(cfg.get("objects") or CORE_OBJECT_TYPES)
    folders = _object_folders(cfg)
    yaml_schemas = {
        schema: globs
        for schema, globs in yaml_schemas.items()
        if not _is_stale_revision_mapping(schema, globs, families=families, folders=folders)
    }
    yaml_schemas.update(mappings)
    existing["yaml.schemas"] = yaml_schemas
    settings_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return ".vscode/settings.json"


def write_vscode_extensions(target: Path, *, merge: bool = True) -> str:
    """Write or merge .vscode/extensions.json recommending the YAML extension."""
    vscode_dir = target / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    extensions_path = vscode_dir / "extensions.json"
    existing = _load_jsonc(extensions_path) if merge and extensions_path.is_file() else {}
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
    mcp: bool = False,
) -> dict[str, object]:
    """Generate prerequisites, then write VS Code settings and/or snippets.

    Deprecation is emitted once at this boundary. Callers must not also call
    ``emit_vscode_deprecation``. ``mcp`` is opt-in and reuses ``write_mcp_config``.
    """
    from opentide.cli.services.generation import run_generate_phases_for_workspace

    if warn_deprecated:
        emit_vscode_deprecation()

    target.mkdir(parents=True, exist_ok=True)

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

    if mcp:
        from opentide.cli.enums import McpHost
        from opentide.cli.services.setup.mcp import write_mcp_config

        files.append(write_mcp_config(target, McpHost.vscode))

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
