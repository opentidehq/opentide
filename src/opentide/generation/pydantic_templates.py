"""Pydantic-driven template generation for core Tide object models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.generation.pydantic_metaschema import build_core_schema_source, core_schema_models
from opentide.generation.template_engine import (
    emit_template_file,
    gen_template,
    get_required,
)
from opentide.models.object_types import CORE_OBJECT_TYPES

CORE_TEMPLATE_MODELS: frozenset[str] = frozenset(CORE_OBJECT_TYPES)


def load_core_template_source(model_key: str) -> dict[str, Any]:
    """Build template-generation source for a core model from Pydantic fields."""
    models = core_schema_models()
    if model_key not in models:
        raise KeyError(f"Unknown core template model {model_key!r}")
    return build_core_schema_source(model_key)


def generate_core_template(
    model_key: str,
    template_path: Path,
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
    )


def core_template_model_keys() -> frozenset[str]:
    """Return registered core object family keys for template generation."""
    return frozenset(core_schema_models())
