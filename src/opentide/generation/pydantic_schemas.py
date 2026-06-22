"""Pydantic-driven JSON Schema generation for core Tide models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentide.generation.schema import model_json_schema
from opentide.generation.schema_utils import strip_framework_keywords
from opentide.models.base import TideModel
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector

CORE_SCHEMA_MODELS: dict[str, type[TideModel]] = {
    "mdr": DetectionRule,
    "dom": DetectionObjective,
    "tvm": ThreatVector,
}


def generate_core_model_schema(model_key: str) -> dict[str, Any]:
    """Generate a JSON Schema dict for a core object model."""
    model = CORE_SCHEMA_MODELS[model_key]
    raw = model_json_schema(model)
    from opentide.generation.schema_pipeline import gen_json_schema

    enriched = gen_json_schema(raw)
    return strip_framework_keywords(enriched)


def export_core_model_schema(model_key: str, output_path: Path) -> None:
    """Write a core model JSON Schema to disk."""
    schema = generate_core_model_schema(model_key)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(schema, indent=4, sort_keys=False, default=str),
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
