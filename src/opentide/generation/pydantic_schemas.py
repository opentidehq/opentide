"""Pydantic-driven JSON Schema generation for core Tide models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentide.generation.model_json_schema import model_json_schema
from opentide.generation.pydantic_metaschema import (
    build_model_schema_source,
)
from opentide.generation.schema_utils import strip_framework_keywords
from opentide.models.base import TideModel
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.models.schema_registry import identifiers_for_families, resolve_model
from opentide.models.version import SchemaVersion
from opentide.registry.artifacts import schema_artifact_name


def pin_schema_identifier(schema: dict[str, Any], identifier: str) -> dict[str, Any]:
    """Pin ``metadata.schema`` to a const in generated JSON Schema."""
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return schema
    metadata = properties.get("metadata")
    if not isinstance(metadata, dict):
        return schema
    meta_props = metadata.setdefault("properties", {})
    if isinstance(meta_props, dict):
        meta_props["schema"] = {"title": "Schema", "const": identifier, "type": "string"}
    return schema


def generate_schema_for_identifier(schema_id: str, *, enrich: bool = True) -> dict[str, Any]:
    """Generate a JSON Schema dict for a registered schema identifier."""
    from opentide.generation.pydantic_metaschema import build_schema_source_for_identifier
    from opentide.generation.schema_pipeline import gen_json_schema

    model = resolve_model(schema_id)
    family = SchemaVersion.parse(schema_id).family
    if enrich and family in CORE_OBJECT_TYPES:
        raw = gen_json_schema(
            build_schema_source_for_identifier(schema_id),
            schema_id=schema_id,
        )
    elif enrich:
        raw = gen_json_schema(build_model_schema_source(model), schema_id=schema_id)
    else:
        raw = model_json_schema(model)
    cleaned = strip_framework_keywords(raw)
    return pin_schema_identifier(cleaned, model.schema_identifier())


def generate_model_schema(model: type[TideModel], *, enrich: bool = True) -> dict[str, Any]:
    """Generate JSON Schema for any registered TideModel."""
    from opentide.generation.schema_pipeline import gen_json_schema

    if enrich:
        raw = build_model_schema_source(model)
        raw = gen_json_schema(raw, schema_id=model.schema_identifier())
    else:
        raw = model_json_schema(model)
    cleaned = strip_framework_keywords(raw)
    return pin_schema_identifier(cleaned, model.schema_identifier())


def export_schema_for_identifier(schema_id: str, output_path: Path) -> None:
    """Write JSON Schema for a registered identifier to disk."""
    schema = generate_schema_for_identifier(schema_id)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(schema, indent=4, sort_keys=False, default=str) + "\n",
        encoding="utf-8",
    )


def export_all_registered_schemas(
    *,
    json_schema_folder: Path,
    schema_map: dict[str, str] | None = None,
) -> None:
    """Export one JSON Schema file per registered core-object identifier."""
    schema_map = schema_map or {}
    for schema_id in identifiers_for_families(CORE_OBJECT_TYPES):
        filename = schema_map.get(schema_id) or schema_artifact_name(schema_id)
        export_schema_for_identifier(schema_id, json_schema_folder / filename)


# Back-compat names used by older callers.
def generate_core_model_schema(model_key: str, *, enrich: bool = True) -> dict[str, Any]:
    """Generate JSON Schema for the latest model of a core object family."""
    from opentide.models.schema_registry import latest_identifier

    return generate_schema_for_identifier(latest_identifier(model_key), enrich=enrich)


def export_core_model_schema(model_key: str, output_path: Path) -> None:
    """Write JSON Schema for the latest core family model to disk."""
    from opentide.models.schema_registry import latest_identifier

    export_schema_for_identifier(latest_identifier(model_key), output_path)


def export_all_core_model_schemas(
    *,
    json_schema_folder: Path,
    json_schema_map: dict[str, str],
) -> None:
    """Export all registered core object schema identifiers."""
    export_all_registered_schemas(json_schema_folder=json_schema_folder, schema_map=json_schema_map)
