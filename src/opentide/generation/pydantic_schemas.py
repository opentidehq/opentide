"""Pydantic-driven JSON Schema generation for core Tide models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentide.generation.pydantic_metaschema import CORE_SCHEMA_MODELS
from opentide.generation.schema import model_json_schema
from opentide.generation.schema_utils import strip_framework_keywords


def generate_core_model_schema(model_key: str, *, enrich: bool = True) -> dict[str, Any]:
    """Generate a JSON Schema dict for a core object model."""
    from opentide.generation.pydantic_metaschema import build_core_schema_source
    from opentide.generation.schema_pipeline import gen_json_schema

    if enrich:
        raw = build_core_schema_source(model_key)
    else:
        raw = model_json_schema(CORE_SCHEMA_MODELS[model_key])
    if enrich:
        raw = gen_json_schema(raw)
    return strip_framework_keywords(raw)


def export_core_model_schema(model_key: str, output_path: Path) -> None:
    """Write a core model JSON Schema to disk."""
    schema = generate_core_model_schema(model_key)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(schema, indent=4, sort_keys=False, default=str) + "\n",
        encoding="utf-8",
    )


def export_all_core_model_schemas(
    *,
    json_schema_folder: Path,
    json_schema_map: dict[str, str],
) -> None:
    """Export all configured core model schemas from Pydantic models."""
    for model_key in CORE_SCHEMA_MODELS:
        if model_key not in json_schema_map:
            continue
        export_core_model_schema(model_key, json_schema_folder / json_schema_map[model_key])
