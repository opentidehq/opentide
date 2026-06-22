"""Pydantic-driven template generation for core Tide object models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from opentide.generation.pydantic_schemas import CORE_SCHEMA_MODELS
from opentide.models.base import TideModel
from opentide.generation.template_engine import (
    emit_template_file,
    gen_template,
    get_required,
)
from opentide.schemas.store import schemas_data_root

CORE_TEMPLATE_MODELS: dict[str, type[TideModel]] = CORE_SCHEMA_MODELS

_CORE_METASCHEMA_FILES: dict[str, str] = {
    "mdr": "MDR Meta Schema.yaml",
    "dom": "Detection Objective.metaschema.yaml",
    "tvm": "Threat Vector.metaschema.yaml",
}


def core_metaschema_path(model_key: str) -> Path:
    """Return bundled metaschema path for a core template model."""
    if model_key not in CORE_TEMPLATE_MODELS:
        raise KeyError(f"Unknown core template model {model_key!r}")
    return schemas_data_root() / _CORE_METASCHEMA_FILES[model_key]


def load_core_template_source(model_key: str) -> dict[str, Any]:
    """Load template-generation source for a core model from the Pydantic schema store."""
    model = CORE_TEMPLATE_MODELS[model_key]
    path = core_metaschema_path(model_key)
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"Invalid metaschema payload for {model_key}")
    # Gate: core object models are registered in the Pydantic pipeline.
    _ = model.schema_identifier()
    return parsed


def generate_core_template(
    model_key: str,
    template_path: Path,
    *,
    log,
) -> None:
    """Generate a YAML template for a core object model."""
    parsed = load_core_template_source(model_key)
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


def core_template_model_keys() -> frozenset[str]:
    """Return registered core template model keys."""
    return frozenset(CORE_TEMPLATE_MODELS)
