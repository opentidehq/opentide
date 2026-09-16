"""Generate VS Code snippets from object and platform templates."""

from __future__ import annotations

import json
import re
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

_CORE_PREFIXES: dict[str, str] = {
    "threat": "tide-threat",
    "objective": "tide-objective",
    "rule": "tide-rule",
}

_EMPTY_SCALAR = re.compile(r"^(\s*)([^:#\n][^:\n]*):\s*$")
_ELIPSIS_LINE = re.compile(r"^(\s*)(\.\.\.)\s*$")


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _next_content_indent(lines: list[str], index: int) -> int | None:
    for candidate in lines[index + 1 :]:
        if not candidate.strip():
            continue
        if candidate.lstrip(" ").startswith("#"):
            continue
        return _indent_width(candidate)
    return None


def _with_tabstops(lines: list[str]) -> list[str]:
    """Turn empty YAML scalars into VS Code tabstops; leave comments alone.

    A key with no value whose next content line is more indented is a mapping
    or list parent, not a fill-in scalar.
    """
    body: list[str] = []
    index = 1
    for line_no, line in enumerate(lines):
        stripped = line.lstrip(" ")
        if stripped.startswith("#"):
            body.append(line)
            continue
        empty = _EMPTY_SCALAR.match(line)
        if empty:
            indent, key = empty.groups()
            child_indent = _next_content_indent(lines, line_no)
            if child_indent is not None and child_indent > _indent_width(line):
                body.append(line)
                continue
            placeholder = key.strip()
            body.append(f"{indent}{key}: ${{{index}:{placeholder}}}")
            index += 1
            continue
        ellipsis = _ELIPSIS_LINE.match(line)
        if ellipsis:
            indent, token = ellipsis.groups()
            body.append(f"{indent}${{{index}:{token}}}")
            index += 1
            continue
        body.append(line)
    return body


def vs_code_snippet_generator(
    template_path: Path | str,
    prefix: str,
    blanks: int = 0,
    *,
    description: str | None = None,
    scope: str = "yaml",
) -> dict[str, Any]:
    """Convert a YAML template file into a VS Code snippet entry.

    Empty values after ``: `` become ``${n:placeholder}`` tabstops. Commented
    optional lines stay comments (issue #194).
    """
    path = Path(template_path)
    raw = path.read_text(encoding="utf-8").splitlines()
    buffer = [""] * blanks
    buffer.extend(_with_tabstops(raw))
    return {
        "prefix": prefix,
        "scope": scope,
        "description": description or prefix,
        "body": buffer,
    }


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


def _require_template(path: Path, *, kind: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {kind} template for snippets: {path}")


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
        title = f"{full_name} Template".strip()
        template_path = templates_dir / templates[model]
        logger.info("generating_snippets_for", arg0=full_name)
        _require_template(template_path, kind=f"core {model}")
        snippets[title] = vs_code_snippet_generator(
            template_path,
            _CORE_PREFIXES.get(str(model), f"tide-{model}"),
            description=title,
        )
    for recomp, subschema_type_folder in recomposition.items():
        entries = config_index.get(recomp)
        if not isinstance(entries, dict):
            entries = config_index.get("platforms")
        if not isinstance(entries, dict):
            continue
        for platform_id, recomp_entry in entries.items():
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
            title = f"{subschema_type_folder} : {subschema_name} Template".strip()
            _require_template(subschema_template_path, kind=f"platform {platform_id}")
            snippets[title] = vs_code_snippet_generator(
                subschema_template_path,
                f"tide-{platform_id}",
                blanks=1,
                description=title,
            )
    snippets_path.parent.mkdir(parents=True, exist_ok=True)
    snippets_path.write_text(
        json.dumps(snippets, indent=4, sort_keys=False, default=str) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    run()
