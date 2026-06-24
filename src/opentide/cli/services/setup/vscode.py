"""Deprecated interim VS Code setup.

Superseded by the OpenTide VS Code extension (bundled language server and templates).
"""

from __future__ import annotations

import json
import os
import warnings
from pathlib import Path

import structlog
import toml

from opentide.cli.services.setup.templates import load_yaml_schema_fragment
from opentide.core.root import get_data_root, get_repo_root

logger = structlog.get_logger("opentide.cli.services.setup.vscode")

DEPRECATION_MESSAGE = (
    "opentide setup vscode is deprecated and will be removed when the OpenTide "
    "VS Code extension ships with a bundled language server and template actions."
)
SNIPPETS_REL = ".vscode/Model Templates.code-snippets"


def emit_vscode_deprecation() -> None:
    warnings.warn(DEPRECATION_MESSAGE, DeprecationWarning, stacklevel=3)
    logger.warning("vscode_setup_deprecated", detail=DEPRECATION_MESSAGE)


def build_yaml_schema_mappings() -> dict[str, str]:
    """Build yaml.schemas mappings from bundled global.toml."""
    global_path = get_data_root() / "configurations" / "global.toml"
    config = toml.loads(global_path.read_text(encoding="utf-8"))
    tide_paths: dict[str, str] = config["paths"]["tide"]
    json_schemas: dict[str, str] = config["json_schemas"]
    schema_dir = tide_paths["json_schemas"].rstrip("/")
    mappings: dict[str, str] = {}
    for object_type, schema_file in json_schemas.items():
        object_path = tide_paths.get(object_type)
        if not object_path:
            continue
        schema_uri = f"{schema_dir}/{schema_file}"
        glob_pattern = f"{object_path.rstrip('/')}/**/*.yaml"
        mappings[schema_uri] = glob_pattern
    return mappings


def write_vscode_settings(target: Path, *, merge: bool = True) -> str:
    """Write or merge .vscode/settings.json with OpenTide yaml.schemas."""
    emit_vscode_deprecation()
    vscode_dir = target / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    settings_path = vscode_dir / "settings.json"
    mappings = build_yaml_schema_mappings()
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
    templates_dir = target / "Schemas" / "Templates"
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
            detail="No templates in Schemas/Templates — run opentide generate first",
        )
        return None

    previous_root = os.environ.get("OPENTIDE_REPO_ROOT")
    get_repo_root.cache_clear()
    os.environ["OPENTIDE_REPO_ROOT"] = str(resolved)
    dest = resolved / SNIPPETS_REL
    dest.parent.mkdir(parents=True, exist_ok=True)
    cwd_previous = Path.cwd()
    try:
        os.chdir(resolved)
        from opentide.generation import vscode_snippets

        vscode_snippets.SNIPPETS_PATH = SNIPPETS_REL
        vscode_snippets.run()
    except FileNotFoundError as exc:
        logger.warning("vscode_snippets_skipped", detail=str(exc))
        return None
    finally:
        os.chdir(cwd_previous)
        get_repo_root.cache_clear()
        if previous_root is None:
            os.environ.pop("OPENTIDE_REPO_ROOT", None)
        else:
            os.environ["OPENTIDE_REPO_ROOT"] = previous_root

    return SNIPPETS_REL if dest.is_file() else None


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
    """Ensure bundled fragment stays aligned with global.toml (tests)."""
    fragment = load_yaml_schema_fragment()
    assert fragment.get("yaml.schemas") == build_yaml_schema_mappings()
