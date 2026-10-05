"""Template generation orchestration — Pydantic FieldInfo as sole YAML source."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.core.logging import get_logger
from opentide.core.logging.console import emit_section
from opentide.core.registry import OpenTide
from opentide.generation.pydantic_skeleton import write_model_template
from opentide.generation.pydantic_templates import (
    core_template_model_keys,
    generate_core_template,
)
from opentide.models.platform_schema import platform_model_for_key
from opentide.models.schema_registry import identifiers_for_families, is_registered, resolve_model
from opentide.registry.artifacts import template_artifact_name

logger = get_logger(__name__)

CONFIG_INDEX: dict[str, Any] = {}
PATHS: dict[str, Any] = {}
PLATFORM_TEMPLATES_FOLDER: Path = Path(".")
RECOMPOSITION: Any = {}


def _schema_id_from_template_filename(filename: str) -> str | None:
    """Map ``rule.1.0.template.yaml`` to ``rule::1.0``. Unversioned names return None."""
    stem = filename.removesuffix(".template.yaml")
    if stem == filename:
        return None
    parts = stem.split(".")
    if len(parts) < 3 or not parts[1].isdigit() or not parts[2].isdigit():
        return None
    return f"{parts[0]}::{int(parts[1])}.{int(parts[2])}"


def _platform_section(entry: dict[str, Any]) -> dict[str, Any]:
    section = entry.get("platform") or entry.get("tide")
    return section if isinstance(section, dict) else {}


def _refresh_renderer_context() -> None:
    """Rebind renderer paths after env or index changes (tests, reload)."""
    global CONFIG_INDEX, PATHS, PLATFORM_TEMPLATES_FOLDER, RECOMPOSITION

    CONFIG_INDEX = OpenTide.Configurations.Index
    PATHS = OpenTide.Configurations.Global.Paths.Index
    PLATFORM_TEMPLATES_FOLDER = Path(PATHS.get("platform_templates", PATHS.get("subschemas", ".")))
    RECOMPOSITION = OpenTide.Configurations.Global.recomposition


def run() -> None:
    _refresh_renderer_context()
    emit_section("Generate Templates from Pydantic Models")
    logger.info(
        "template_generation_started",
        detail="Core and platform templates are generated from Pydantic FieldInfo.",
    )

    templates = OpenTide.Configurations.Global.templates
    templates_dir = Path(PATHS["templates"])
    for meta in OpenTide.Configurations.Global.metaschemas:
        if meta not in templates or meta not in core_template_model_keys():
            continue
        written: set[Path] = set()
        for schema_id in identifiers_for_families((meta,)):
            model = resolve_model(schema_id)
            versioned = templates_dir / template_artifact_name(schema_id)
            logger.info("generating_template", detail=schema_id)
            write_model_template(versioned, model, schema_id=schema_id)
            written.add(versioned.resolve())
        configured = templates_dir / templates[meta]
        if configured.resolve() in written:
            continue
        pinned = _schema_id_from_template_filename(str(templates[meta]))
        logger.info("generating_template", detail=str(meta))
        if pinned and is_registered(pinned):
            write_model_template(configured, resolve_model(pinned), schema_id=pinned)
        else:
            generate_core_template(meta, configured)

    for recomp in RECOMPOSITION:
        subschema_type_folder = RECOMPOSITION[recomp]
        recomp_configs = CONFIG_INDEX.get(recomp, {})
        if not isinstance(recomp_configs, dict):
            recomp_configs = CONFIG_INDEX.get("platforms", {})
        for entry, recomp_entry in recomp_configs.items():
            if not isinstance(recomp_entry, dict):
                continue
            platform_section = _platform_section(recomp_entry)
            if not platform_section or platform_section.get("enabled") is not True:
                continue

            subschema_name = (
                platform_section.get("name") or platform_section.get("subschema") or entry
            )

            subschema_template_path = (
                PLATFORM_TEMPLATES_FOLDER
                / subschema_type_folder
                / "Templates"
                / f"{subschema_name} Template.yaml"
            )
            platform_model = platform_model_for_key(entry)
            logger.info("generating_template", detail=subschema_name)
            write_model_template(subschema_template_path, platform_model, indent=2)

    logger.info("all_templates_correctly_generated")


if __name__ == "__main__":
    run()
