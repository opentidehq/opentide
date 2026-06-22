"""Template generation orchestration — core models via Pydantic pipeline."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import git

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from opentide.core.logging import log
from opentide.core.registry import OpenTide
from opentide.generation.pydantic_templates import (
    core_template_model_keys,
    generate_core_template,
)
from opentide.generation.template_engine import (
    emit_template_file,
    gen_template,
    get_required,
)

CONFIG_INDEX: dict[str, Any]
PATHS: dict[str, Any]
SUBSCHEMAS_FOLDER: Path
RECOMPOSITION: Any


def _refresh_renderer_context() -> None:
    """Rebind renderer paths after env or index changes (tests, reload)."""
    global CONFIG_INDEX, PATHS, SUBSCHEMAS_FOLDER, RECOMPOSITION

    CONFIG_INDEX = OpenTide.Configurations.Index
    PATHS = OpenTide.Configurations.Global.Paths.Index
    SUBSCHEMAS_FOLDER = Path(PATHS["subschemas"])
    RECOMPOSITION = OpenTide.Configurations.Global.recomposition


def _ensure_tide_index() -> None:
    """Ensure OpenTide index includes metaschemas/subschemas for template generation."""
    index = getattr(OpenTide, "_index", None)
    if not getattr(OpenTide, "_initialised", False) or index is None or "subschemas" not in index:
        OpenTide.reload()


def run() -> None:
    _ensure_tide_index()
    _refresh_renderer_context()
    log("TITLE", "Generate Templates from Pydantic Core Models")
    log(
        "INFO",
        "Core object templates are generated from the Pydantic schema store; "
        "platform subschema templates retain metaschema sources.",
    )

    templates = OpenTide.Configurations.Global.templates
    for meta in OpenTide.Configurations.Global.metaschemas:
        if meta not in templates:
            continue
        template_path = Path(PATHS["templates"]) / templates[meta]
        log("ONGOING", "Generating template", str(meta))

        if meta in core_template_model_keys():
            generate_core_template(meta, template_path, log=log)
            continue

        parsed = OpenTide.TideSchemas.Index[meta]
        placeholders: dict[str, str] = parsed.get("tide.placeholders") or {}
        required = get_required(parsed["properties"], list(parsed.get("required", [])))
        required.extend(parsed.get("tide.template.force-required") or [])
        template_body = gen_template(parsed["properties"], required)
        emit_template_file(
            template_path,
            template_body,
            placeholders=placeholders,
            spacing_properties=parsed["properties"],
            indent=None,
            log=log,
        )

    for recomp in RECOMPOSITION:
        subschema_type_folder = RECOMPOSITION[recomp]
        for entry in CONFIG_INDEX[recomp]:
            recomp_entry = CONFIG_INDEX[recomp][entry]
            enabled = False
            try:
                if recomp_entry["tide"]["enabled"] is True:
                    enabled = True
            except Exception:
                if recomp_entry["platform"]["enabled"] is True:
                    enabled = True

            if not enabled:
                continue

            try:
                subschema_name = recomp_entry["tide"]["name"]
            except Exception:
                subschema_name = recomp_entry["platform"]["name"]

            subschema_template_path = (
                SUBSCHEMAS_FOLDER
                / subschema_type_folder
                / "Templates"
                / f"{subschema_name} Template.yaml"
            )
            parsed = OpenTide.TideSchemas.subschemas[recomp][entry]
            log("ONGOING", "Generating template", subschema_name)
            required = get_required(parsed["properties"], list(parsed.get("required", [])))
            required.extend(parsed.get("tide.template.force-required") or [])
            subschema_template = gen_template(parsed["properties"], required)
            emit_template_file(
                subschema_template_path,
                subschema_template,
                placeholders=None,
                spacing_properties=parsed["properties"],
                indent=2,
                log=log,
            )

    log("SUCCESS", "All Templates correctly generated")


if __name__ == "__main__":
    run()
