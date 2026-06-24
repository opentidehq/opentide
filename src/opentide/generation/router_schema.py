"""Generate opentide.schema.json router for IDE validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentide.models.schema_registry import registered_identifiers
from opentide.registry.artifacts import schema_artifact_name


def _if_then_branch(schema_id: str, ref: str) -> dict[str, Any]:
    return {
        "if": {
            "properties": {
                "metadata": {
                    "properties": {"schema": {"const": schema_id}},
                    "required": ["schema"],
                }
            },
            "required": ["metadata"],
        },
        "then": {"$ref": ref},
    }


def build_opentide_router(identifiers: list[str] | None = None) -> dict[str, Any]:
    """Build umbrella JSON Schema routing on metadata.schema."""
    ids = identifiers or registered_identifiers()
    branches = [
        _if_then_branch(schema_id, f"./{schema_artifact_name(schema_id)}") for schema_id in ids
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://opentide.dev/schemas/opentide.schema.json",
        "title": "OpenTide Object Router",
        "oneOf": branches,
    }


def export_opentide_router(output_path: Path, identifiers: list[str] | None = None) -> None:
    """Write router schema to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    router = build_opentide_router(identifiers)
    output_path.write_text(json.dumps(router, indent=4) + "\n", encoding="utf-8")
