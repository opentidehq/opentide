"""Generate VS Code snippets from object and platform templates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from opentide.core.logging.console import emit_section
from opentide.core.registry import OpenTide

logger = structlog.get_logger("opentide.generation.vscode_snippets")

# Overridable output path. ``opentide setup vscode`` assigns this before ``run()``.
# Must stay unset at import time: evaluating ``Paths.Core.subschemas`` on import
# crashed fresh repositories after the platform_templates rename (issue #153).
SNIPPETS_PATH: str | Path | None = None


def vs_code_snippet_generator(template_path, prefix, blanks=0):
    """
    Generates the body of a snippet by reading the file lines by line, which
    when dumped to json creates an array of strings preserving spaces as per
    vscode requirement.

    Parameters
    ----------
    template_path : path of the template file to convert to vscode snippet
    description : description of the snippet (will be shown to user)
    prefix : keywords that will trigger intellisense

    Returns
    -------
    snippet : snippet body, to be assembled in final snippet json file

    """
    path = Path(template_path)
    buffer = [""] * blanks
    buffer.extend(path.read_text(encoding="utf-8").splitlines())
    return {"prefix": prefix, "body": buffer}


def _platform_templates_dir(core: Any) -> Path:
    """Resolve bundled platform templates (legacy name: subschemas)."""
    raw = getattr(core, "platform_templates", None) or getattr(core, "subschemas", None)
    if raw is None:
        raise AttributeError("platform template path is not configured")
    return Path(raw)


def _snippets_output_path(paths: Any) -> Path:
    if SNIPPETS_PATH is not None:
        return Path(str(SNIPPETS_PATH))
    return Path(str(paths.Tide.snippet_file))


def _entry_enabled(recomp_entry: dict[str, Any]) -> bool:
    for section in ("tide", "platform"):
        block = recomp_entry.get(section)
        if isinstance(block, dict) and block.get("enabled") is True:
            return True
    return False


def _entry_name(recomp_entry: dict[str, Any]) -> str | None:
    for section in ("tide", "platform"):
        block = recomp_entry.get(section)
        if isinstance(block, dict) and block.get("name"):
            return str(block["name"])
    return None


def run() -> None:
    emit_section("Generate VSCode Snippets")
    logger.info("converts_the_templates_into_vscode_formatted_snippets_inproject")
    paths = OpenTide.Configurations.Global.Paths
    snippets_path = _snippets_output_path(paths)
    templates_dir = Path(str(paths.Tide.templates))
    subschemas_folder = _platform_templates_dir(paths.Core)
    recomposition = OpenTide.Configurations.Global.recomposition
    config_index = OpenTide.Configurations.Index
    metaschemas = OpenTide.Configurations.Global.metaschemas
    templates = OpenTide.Configurations.Global.templates
    object_names = OpenTide.Configurations.Documentation.object_names

    snippets: dict[str, Any] = {}
    for model in metaschemas:
        if model not in templates:
            continue
        full_name = object_names.get(model, model)
        keyword = f"{full_name} Template".strip()
        template_path = templates_dir / templates[model]
        logger.info("generating_snippets_for", arg0=full_name)
        if not template_path.is_file():
            logger.warning("snippet_template_missing", path=str(template_path))
            continue
        snippets[keyword] = vs_code_snippet_generator(template_path, keyword)
    for recomp, subschema_type_folder in recomposition.items():
        entries = config_index.get(recomp)
        if not isinstance(entries, dict):
            continue
        for recomp_entry in entries.values():
            if not isinstance(recomp_entry, dict) or not _entry_enabled(recomp_entry):
                continue
            subschema_name = _entry_name(recomp_entry)
            if not subschema_name:
                continue
            logger.info("generating_snippets_for", arg0=subschema_name)
            subchema_template_name = f"{subschema_name} Template.yaml"
            subschema_template_path = (
                subschemas_folder / subschema_type_folder / "Templates" / subchema_template_name
            )
            keyword = f"{subschema_type_folder} : {subschema_name} Template".strip()
            if not subschema_template_path.is_file():
                logger.warning("snippet_template_missing", path=str(subschema_template_path))
                continue
            snippets[keyword] = vs_code_snippet_generator(
                subschema_template_path, keyword, blanks=1
            )
    snippets_path.parent.mkdir(parents=True, exist_ok=True)
    snippets_path.write_text(
        json.dumps(snippets, indent=4, sort_keys=False, default=str) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    run()
