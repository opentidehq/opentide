"""Template generation orchestration — Pydantic FieldInfo as sole YAML source."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.core.lint_config import parse_lint_config
from opentide.core.logging import get_logger
from opentide.core.progress import report_stage
from opentide.core.registry import Opentide
from opentide.generation.pydantic_skeleton import write_model_template
from opentide.generation.pydantic_templates import (
    core_template_model_keys,
    generate_core_template,
)
from opentide.models.platform_schema import platform_model_for_key
from opentide.models.schema_registry import identifiers_for_families, is_registered, resolve_model
from opentide.package.paths import platform_template_name, platform_templates_root
from opentide.registry.artifacts import template_artifact_name

logger = get_logger(__name__)

CONFIG_INDEX: dict[str, Any] = {}
PATHS: dict[str, Any] = {}

#: Folder under the workspace templates directory that holds platform block templates.
PLATFORM_TEMPLATES_DIR = "platforms"


def _schema_id_from_template_filename(filename: str) -> str | None:
    """Map ``rule.1.0.template.yaml`` to ``rule::1.0``. Unversioned names return None."""
    stem = filename.removesuffix(".template.yaml")
    if stem == filename:
        return None
    parts = stem.split(".")
    if len(parts) < 3 or not parts[1].isdigit() or not parts[2].isdigit():
        return None
    return f"{parts[0]}::{int(parts[1])}.{int(parts[2])}"


def enabled_platforms(configurations: dict[str, Any]) -> list[str]:
    """Platforms with a rule block whose merged ``[platform] enabled`` is true, in file order.

    A plugin's ``platforms/<id>.toml`` has no rule-block model, so no
    template or snippet (#736).
    """
    from opentide.models.platform import PLATFORM_CONFIG_MODELS

    platforms = configurations.get("platforms")
    if not isinstance(platforms, dict):
        return []
    enabled: list[str] = []
    for identifier, document in platforms.items():
        if identifier not in PLATFORM_CONFIG_MODELS:
            continue
        section = document.get("platform") if isinstance(document, dict) else None
        if isinstance(section, dict) and section.get("enabled") is True:
            enabled.append(str(identifier))
    return enabled


def platform_template_path(templates_dir: Path, platform: str) -> Path:
    """Where ``generate templates`` writes *platform*'s block template."""
    return templates_dir / PLATFORM_TEMPLATES_DIR / platform_template_name(platform)


def write_bundled_platform_templates(directory: Path | None = None) -> list[Path]:
    """Render every platform's block template into the package (or *directory*).

    For maintainers: run after changing a platform model, so the bundled
    templates the golden test compares stay in step.
    """
    from opentide.models.platform import PLATFORM_CONFIG_MODELS

    target = directory or platform_templates_root()
    written: list[Path] = []
    for platform in sorted(PLATFORM_CONFIG_MODELS):
        path = target / platform_template_name(platform)
        write_model_template(path, platform_model_for_key(platform), indent=2)
        written.append(path)
    return written


def _refresh_renderer_context() -> None:
    """Rebind renderer paths after env or index changes (tests, reload)."""
    global CONFIG_INDEX, PATHS

    CONFIG_INDEX = Opentide.Configurations.Index
    PATHS = Opentide.Configurations.Global.Paths.Index


def run() -> None:
    _refresh_renderer_context()
    report_stage("templates from models")
    logger.info(
        "template_generation_started",
        detail="Core and platform templates are generated from Pydantic FieldInfo.",
    )

    templates = Opentide.Configurations.Global.templates
    templates_dir = Path(PATHS["templates"])
    # Keys ``opentide lint`` requires render live, so scaffolds pass the metadata check.
    required_metadata = parse_lint_config(CONFIG_INDEX.get("lint")).required_metadata
    for meta in Opentide.Configurations.Global.metaschemas:
        if meta not in templates or meta not in core_template_model_keys():
            continue
        written: set[Path] = set()
        for schema_id in identifiers_for_families((meta,)):
            model = resolve_model(schema_id)
            versioned = templates_dir / template_artifact_name(schema_id)
            logger.info("generating_template", detail=schema_id)
            write_model_template(
                versioned, model, schema_id=schema_id, required_metadata=required_metadata
            )
            written.add(versioned.resolve())
        configured = templates_dir / templates[meta]
        if configured.resolve() in written:
            continue
        pinned = _schema_id_from_template_filename(str(templates[meta]))
        logger.info("generating_template", detail=str(meta))
        if pinned and is_registered(pinned):
            write_model_template(
                configured,
                resolve_model(pinned),
                schema_id=pinned,
                required_metadata=required_metadata,
            )
        else:
            generate_core_template(meta, configured, required_metadata=required_metadata)

    for platform in enabled_platforms(CONFIG_INDEX):
        logger.info("generating_template", detail=platform)
        write_model_template(
            platform_template_path(templates_dir, platform),
            platform_model_for_key(platform),
            indent=2,
        )

    logger.info("all_templates_correctly_generated")


if __name__ == "__main__":
    run()
