"""Deprecated interim VS Code setup.

Superseded by the opentide VS Code extension (``opentidehq.opentide``), which
bundles the language server, the templates and the MCP server. This module
recommends that extension and writes the snippets. It no longer maps object
files to JSON schemas for a YAML extension: the opentide language server owns
their diagnostics, so a merge removes the mapping earlier releases wrote.
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


#: The opentide VS Code extension: language server, templates, snippets and MCP server.
EXTENSION_ID = "opentidehq.opentide"

RECOMMENDED_EXTENSIONS: tuple[str, ...] = (EXTENSION_ID,)

#: What ``setup mcp --vscode`` and ``doctor`` say when the workspace recommends the extension.
EXTENSION_MCP_NOTE = (
    f"The opentide VS Code extension ({EXTENSION_ID}), which .vscode/extensions.json "
    "recommends, provides the opentide MCP server to VS Code; .vscode/mcp.json is for "
    "teammates without it"
)


def recommends_extension(workspace: Path) -> bool:
    """Whether ``.vscode/extensions.json`` recommends the opentide extension."""
    path = workspace / ".vscode" / "extensions.json"
    if not path.is_file():
        return False
    try:
        data = _load_jsonc(path)
    except ValueError:
        return False
    recommendations = data.get("recommendations") if isinstance(data, dict) else None
    return isinstance(recommendations, list) and EXTENSION_ID in recommendations


def emit_vscode_deprecation() -> None:
    warnings.warn(DEPRECATION_MESSAGE, DeprecationWarning, stacklevel=3)
    from opentide.cli.ui.mode import OutputMode, get_mode

    if get_mode() in (OutputMode.JSON, OutputMode.MCP):
        logger.warning("vscode_setup_deprecated", detail=DEPRECATION_MESSAGE)
        return
    # Printed through the log it read "warning: Vscode setup deprecated · detail:
    # opentide setup vscode is deprecated …", an event slug (post-merge run).
    from opentide.cli.ui.render import render_warnings
    from opentide.core.logging.config import get_console

    render_warnings(get_console(), [DEPRECATION_MESSAGE.rstrip(".")])


def _paths_config() -> dict[str, Any]:
    configs = resolve_configurations()
    return configs["paths"]


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
    """The ``yaml.schemas`` entry releases before #752 wrote: objects to the router schema.

    ``setup vscode`` no longer writes it; :func:`write_vscode_settings` and
    ``doctor`` use it to recognise it.
    """
    del workspace  # reserved for future workspace-relative schema URIs
    cfg = _paths_config()
    return {_router_schema_uri(cfg): _object_glob(_object_folders(cfg))}


def is_opentide_schema_mapping(schema: str, globs: object) -> bool:
    """Whether a ``yaml.schemas`` entry is one ``setup vscode`` wrote.

    The router schema (``.opentide/schemas/opentide.schema.json``), whatever it
    maps, or a per-folder revision mapping of an earlier release. A mapping of
    another schema, or of a revision schema to the user's own folders, is theirs.
    """
    cfg = _paths_config()
    if schema.removeprefix("./") == _router_schema_uri(cfg):
        return True
    families = list(cfg.get("objects") or CORE_OBJECT_TYPES)
    return _is_stale_revision_mapping(
        schema, globs, families=families, folders=_object_folders(cfg)
    )


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


def write_vscode_settings(target: Path) -> str | None:
    """Remove the ``yaml.schemas`` entries opentide wrote from ``.vscode/settings.json``.

    The opentide extension's language server checks object files, and a YAML
    language server mapped to opentide's schemas would report them a second
    time. Every other setting and ``yaml.schemas`` entry is kept; an emptied
    ``yaml.schemas`` is removed. The file is never created, and is left
    untouched when it has no such entry. Returns the path when it was rewritten.
    """
    settings_path = target / ".vscode" / "settings.json"
    if not settings_path.is_file():
        return None
    existing = _load_jsonc(settings_path)
    if not isinstance(existing, dict):
        return None
    yaml_schemas = existing.get("yaml.schemas")
    if not isinstance(yaml_schemas, dict):
        return None
    kept = {
        schema: globs
        for schema, globs in yaml_schemas.items()
        if not is_opentide_schema_mapping(str(schema), globs)
    }
    if kept == yaml_schemas:
        return None
    if kept:
        existing["yaml.schemas"] = kept
    else:
        del existing["yaml.schemas"]
    settings_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return ".vscode/settings.json"


def write_vscode_extensions(target: Path, *, merge: bool = True) -> str:
    """Write or merge .vscode/extensions.json recommending the opentide extension.

    Recommendations already there are kept, and one the file lists under
    ``unwantedRecommendations`` is not added.
    """
    vscode_dir = target / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    extensions_path = vscode_dir / "extensions.json"
    existing = _load_jsonc(extensions_path) if merge and extensions_path.is_file() else {}
    if not isinstance(existing, dict):
        existing = {}
    recommendations = existing.get("recommendations", [])
    if not isinstance(recommendations, list):
        recommendations = []
    unwanted = existing.get("unwantedRecommendations")
    unwanted = unwanted if isinstance(unwanted, list) else []
    for extension_id in RECOMMENDED_EXTENSIONS:
        if extension_id not in recommendations and extension_id not in unwanted:
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


def _settings_files(target: Path, *, merge: bool) -> list[str]:
    """Recommend the extension; drop opentide's ``yaml.schemas`` entries."""
    files = [write_vscode_extensions(target, merge=merge)]
    if (settings := write_vscode_settings(target)) is not None:
        files.append(settings)
    return files


def run_vscode_settings(target: Path, *, merge: bool = True) -> dict[str, object]:
    return {"message": "VS Code settings generated", "files": _settings_files(target, merge=merge)}


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
        files.extend(_settings_files(target, merge=merge))

    snippet_path: str | None = None
    if snippets:
        snippet_path = run_vscode_snippets(target)
        if snippet_path:
            files.append(snippet_path)

    warnings: list[str] = []
    if mcp:
        from opentide.cli.enums import McpHost
        from opentide.cli.services.setup.mcp import (
            McpConfigError,
            mcp_config_warning,
            write_mcp_config,
        )

        try:
            files.append(write_mcp_config(target, McpHost.vscode))
        except McpConfigError as exc:
            warnings.append(mcp_config_warning(McpHost.vscode, exc))
    extension_mcp = mcp and recommends_extension(target)

    payload: dict[str, object] = {
        "message": "VS Code setup complete (deprecated)",
        "files": files,
        "generated": generated,
        "deprecated": DEPRECATION_MESSAGE,
        "status": "completed",
    }
    if warnings:
        payload["warnings"] = warnings
    if extension_mcp:
        payload["extension_mcp"] = True
        payload["detail"] = EXTENSION_MCP_NOTE
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
