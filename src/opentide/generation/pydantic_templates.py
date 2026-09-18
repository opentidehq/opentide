"""Pydantic-driven template generation for core Tide object models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.generation.pydantic_metaschema import build_core_schema_source, core_schema_models
from opentide.generation.pydantic_skeleton import write_model_template
from opentide.models.object_types import CORE_OBJECT_TYPES

CORE_TEMPLATE_MODELS: frozenset[str] = frozenset(CORE_OBJECT_TYPES)


def load_core_template_source(model_key: str) -> dict[str, Any]:
    """Build JSON Schema source for a core model (not used for YAML skeletons)."""
    models = core_schema_models()
    if model_key not in models:
        raise KeyError(f"Unknown core template model {model_key!r}")
    return build_core_schema_source(model_key)


def generate_core_template(
    model_key: str,
    template_path: Path,
) -> None:
    """Generate a YAML template for a core object model from FieldInfo."""
    models = core_schema_models()
    if model_key not in models:
        raise KeyError(f"Unknown core template model {model_key!r}")
    model = models[model_key]
    write_model_template(
        template_path,
        model,
        schema_id=model.schema_identifier(),
    )


def core_template_model_keys() -> frozenset[str]:
    """Return registered core object family keys for template generation."""
    return frozenset(core_schema_models())
