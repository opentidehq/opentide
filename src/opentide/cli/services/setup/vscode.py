"""Deprecated interim VS Code setup.

Superseded by the OpenTide VS Code extension (bundled language server and templates).
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import warnings
from pathlib import Path

import structlog

from opentide.cli.services.setup.templates import load_yaml_schema_fragment
from opentide.core.files import resolve_configurations
from opentide.core.root import get_repo_root
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


def emit_vscode_deprecation() -> None:
    warnings.warn(DEPRECATION_MESSAGE, DeprecationWarning, stacklevel=3)
    logger.warning("vscode_setup_deprecated", detail=DEPRECATION_MESSAGE)


def build_yaml_schema_mappings(*, workspace: Path | None = None) -> dict[str, str]:
    """Build yaml.schemas mappings from bundled paths.toml."""
    configs = resolve_configurations()
    cfg = configs.get("paths") or configs["global"]
    artifacts = cfg.get("artifacts", {})
    schema_map: dict[str, str] = dict(artifacts.get("schemas", cfg.get("json_schemas", {})))
    router_name = schema_map.get("router", "opentide.schema.json")
    schema_uri = f"{OPENTIDE_DIR}/schemas/{router_name}"
    return {schema_uri: "objects/**/*.yaml"}


def write_vscode_settings(target: Path, *, merge: bool = True) -> str:
    """Write or merge .vscode/settings.json with OpenTide yaml.schemas."""
    emit_vscode_deprecation()
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
    yaml_schemas.update(mappings)
    existing["yaml.schemas"] = yaml_schemas
    settings_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return ".vscode/settings.json"


def _templates_ready(target: Path) -> bool:
    templates_dir = target / OPENTIDE_DIR / "templates"
    if not templates_dir.is_dir():
        return False
    return any(templates_dir.glob("*.yaml")) or any(templates_dir.glob("*.yml"))


def run_vscode_snippets(target: Path) -> str | None:
    """Generate VS Code snippets under ``target``; returns relative path or None."""
    emit_vscode_deprecation()
    resolved = target.resolve()
    if not _templates_ready(resolved):
        logger.warning(
            "vscode_snippets_skipped",
            detail=f"No templates in {OPENTIDE_DIR}/templates — run opentide generate first",
        )
        return None

    previous_root = os.environ.get("OPENTIDE_REPO_ROOT")
    previous_workspace = os.environ.get("OPENTIDE_TIDE_WORKSPACE")
    get_repo_root.cache_clear()
    os.environ["OPENTIDE_REPO_ROOT"] = str(resolved)
    os.environ["OPENTIDE_TIDE_WORKSPACE"] = str(resolved)
    from opentide.core.index_manager import IndexManager

    IndexManager._cache = None
    snippets_rel = snippet_file_rel(workspace=resolved)
    dest = resolved / snippets_rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    cwd_previous = Path.cwd()
    vscode_snippets = None
    try:
        os.chdir(resolved)
        vscode_snippets = importlib.import_module("opentide.generation.vscode_snippets")
        vscode_snippets.SNIPPETS_PATH = snippets_rel
        vscode_snippets.run()
    except FileNotFoundError as exc:
        logger.warning("vscode_snippets_skipped", detail=str(exc))
        return None
    finally:
        os.chdir(cwd_previous)
        module = vscode_snippets or sys.modules.get("opentide.generation.vscode_snippets")
        if module is not None and hasattr(module, "SNIPPETS_PATH"):
            module.SNIPPETS_PATH = None
        get_repo_root.cache_clear()
        IndexManager._cache = None
        if previous_root is None:
            os.environ.pop("OPENTIDE_REPO_ROOT", None)
        else:
            os.environ["OPENTIDE_REPO_ROOT"] = previous_root
        if previous_workspace is None:
            os.environ.pop("OPENTIDE_TIDE_WORKSPACE", None)
        else:
            os.environ["OPENTIDE_TIDE_WORKSPACE"] = previous_workspace

    return snippets_rel if dest.is_file() else None


def run_vscode_settings(target: Path, *, merge: bool = True) -> dict[str, object]:
    rel = write_vscode_settings(target, merge=merge)
    return {"message": "VS Code settings generated", "files": [rel]}


def run_vscode_all(target: Path, *, merge: bool = True) -> dict[str, object]:
    settings = run_vscode_settings(target, merge=merge)
    files = list(settings["files"])
    snippet_path = run_vscode_snippets(target)
    if snippet_path:
        files.append(snippet_path)
    return {
        "message": "VS Code setup generated (deprecated)",
        "files": files,
        "deprecated": DEPRECATION_MESSAGE,
    }


def validate_schema_fragment_matches_global() -> None:
    """Ensure bundled fragment stays aligned with paths.toml (tests)."""
    fragment = load_yaml_schema_fragment()
    assert fragment.get("yaml.schemas") == build_yaml_schema_mappings()
