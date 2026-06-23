"""Template generation orchestration — Pydantic models as sole source."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.core.logging import log
from opentide.core.registry import OpenTide
from opentide.generation.pydantic_metaschema import build_platform_schema_source
from opentide.generation.pydantic_templates import (
    core_template_model_keys,
    generate_core_template,
)
from opentide.generation.template_engine import (
    emit_template_file,
    gen_template,
    get_required,
)
from opentide.models.platform_schema import platform_model_for_key

CONFIG_INDEX: dict[str, Any]
PATHS: dict[str, Any]
PLATFORM_TEMPLATES_FOLDER: Path
RECOMPOSITION: Any


def _refresh_renderer_context() -> None:
    """Rebind renderer paths after env or index changes (tests, reload)."""
    global CONFIG_INDEX, PATHS, PLATFORM_TEMPLATES_FOLDER, RECOMPOSITION

    CONFIG_INDEX = OpenTide.Configurations.Index
    PATHS = OpenTide.Configurations.Global.Paths.Index
    PLATFORM_TEMPLATES_FOLDER = Path(PATHS.get("platform_templates", PATHS.get("subschemas", ".")))
    RECOMPOSITION = OpenTide.Configurations.Global.recomposition


def run() -> None:
    _refresh_renderer_context()
    log("TITLE", "Generate Templates from Pydantic Models")
    log(
        "INFO",
        "Core and platform templates are generated from Pydantic model metadata.",
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
                PLATFORM_TEMPLATES_FOLDER
                / subschema_type_folder
                / "Templates"
                / f"{subschema_name} Template.yaml"
            )
            platform_model = platform_model_for_key(entry)
            parsed = build_platform_schema_source(platform_model)
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
