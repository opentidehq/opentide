"""Generate opentide.schema.json, the editor entry point routing on ``metadata.schema``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentide.generation.schema_annotations import annotate_editor_schema
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.models.schema_registry import identifiers_for_families
from opentide.models.version import SchemaVersion
from opentide.registry.artifacts import schema_artifact_name

ROUTER_TITLE = "opentide Object Router"
_FAMILY_LABELS = {
    "threat": "Threat Vector",
    "objective": "Detection Objective",
    "rule": "Detection Rule",
}


def _identifier_label(schema_id: str) -> str:
    version = SchemaVersion.parse(schema_id)
    family = _FAMILY_LABELS.get(version.family, version.family.capitalize())
    return f"{family}, schema revision {version.major}.{version.minor}"


def _route(schema_id: str) -> dict[str, Any]:
    """Apply one revision schema when ``metadata.schema`` equals ``schema_id``.

    Branches are combined with ``allOf``: a branch whose ``if`` does not match
    contributes nothing, so exactly one revision schema validates an object.
    ``type: object`` keeps a scalar document or ``metadata`` from vacuously
    matching every ``if``. The ``$ref`` is relative and the router has no
    ``$id``, so it resolves to the sibling file next to the router.
    """
    return {
        "if": {
            "type": "object",
            "required": ["metadata"],
            "properties": {
                "metadata": {
                    "type": "object",
                    "required": ["schema"],
                    "properties": {"schema": {"const": schema_id}},
                }
            },
        },
        "then": {"$ref": schema_artifact_name(schema_id)},
    }


def build_opentide_router(identifiers: list[str] | None = None) -> dict[str, Any]:
    """Build the router schema that selects a revision schema from ``metadata.schema``.

    ``identifiers`` defaults to every registered core-object identifier. The
    identifiers are also offered as an ``enum`` on ``metadata.schema``, so an
    editor completes them and reports an unknown identifier on that field.
    """
    ids = sorted(identifiers or identifiers_for_families(CORE_OBJECT_TYPES))
    router: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": ROUTER_TITLE,
        "description": (
            "Validates any opentide object against the schema revision named in "
            "metadata.schema. Map objects/**/*.yaml to this file in the editor."
        ),
        "type": "object",
        "required": ["metadata"],
        "properties": {
            "metadata": {
                "title": "Metadata",
                "description": "Object metadata. `schema` selects the revision schema.",
                "type": "object",
                "required": ["schema"],
                "properties": {
                    "schema": {
                        "title": "Schema",
                        "description": (
                            "Schema identifier (family::major.minor). Selects the "
                            "revision schema that validates this object."
                        ),
                        "type": "string",
                        "enum": ids,
                        "enumDescriptions": [_identifier_label(schema_id) for schema_id in ids],
                    }
                },
            }
        },
        "allOf": [_route(schema_id) for schema_id in ids],
    }
    return annotate_editor_schema(router)


def export_opentide_router(output_path: Path, identifiers: list[str] | None = None) -> None:
    """Write router schema to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    router = build_opentide_router(identifiers)
    output_path.write_text(json.dumps(router, indent=4) + "\n", encoding="utf-8")
