"""MCP resource providers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel

from opentide.core.io import dump_json_text
from opentide.core.registry import OpenTide
from opentide.mcp_server.catalog import ensure_initialised, get_object

_FAMILY_ALIASES = {
    "rules": "rule",
    "threats": "threat",
    "objectives": "objective",
    "visibilities": "visibility",
}


def _json_ready(payload: Any) -> Any:
    """Expand Pydantic models so resources serialise as JSON, not ``repr()``."""
    if isinstance(payload, BaseModel):
        return payload.model_dump(mode="json", by_alias=True)
    if isinstance(payload, Mapping):
        return {str(key): _json_ready(value) for key, value in payload.items()}
    if isinstance(payload, (list, tuple, set, frozenset)):
        return [_json_ready(item) for item in payload]
    return payload


def _json_resource(payload: Any) -> str:
    return dump_json_text(_json_ready(payload), indent=True, default=str)


def _split_schema_id(identifier: str) -> tuple[str, str | None]:
    """Split ``rule::1.0`` / ``rule.1.0`` / ``rule`` into family and version."""
    text = identifier.strip()
    if "::" in text:
        family, _, version = text.partition("::")
    elif "." in text:
        family, _, version = text.partition(".")
    else:
        family, version = text, ""
    family = family.strip().lower()
    return _FAMILY_ALIASES.get(family, family), version.strip() or None


def _version_order(version: str) -> tuple[tuple[int, int | str], ...]:
    return tuple((0, int(chunk)) if chunk.isdigit() else (1, chunk) for chunk in version.split("."))


def _resolve_family_key(index: Mapping[str, Any], requested: str) -> str | None:
    """Map a family alias onto a schema-id key such as ``rule::1.0``."""
    if requested in index:
        return requested
    family, version = _split_schema_id(requested)
    candidates: list[tuple[tuple[tuple[int, int | str], ...], str]] = []
    for key in index:
        key_family, key_version = _split_schema_id(str(key))
        if key_family != family:
            continue
        if version is not None and key_version != version:
            continue
        candidates.append((_version_order(key_version or "0"), str(key)))
    if not candidates:
        return None
    return max(candidates)[1]


def resource_index() -> str:
    ensure_initialised()
    return _json_resource(OpenTide.Index)


def resource_rules() -> str:
    ensure_initialised()
    return _json_resource(OpenTide.Models.rules)


def resource_rule(uuid: str) -> str:
    found = get_object(uuid)
    if found is None or found["type"] != "rule":
        return _json_resource({"error": f"Rule {uuid} not found"})
    return _json_resource(found["body"])


def resource_threats() -> str:
    ensure_initialised()
    return _json_resource(OpenTide.Models.threats)


def resource_threat(uuid: str) -> str:
    found = get_object(uuid)
    if found is None or found["type"] != "threat":
        return _json_resource({"error": f"Threat {uuid} not found"})
    return _json_resource(found["body"])


def resource_objectives() -> str:
    ensure_initialised()
    return _json_resource(OpenTide.Models.objectives)


def resource_objective(uuid: str) -> str:
    found = get_object(uuid)
    if found is None or found["type"] != "objective":
        return _json_resource({"error": f"Objective {uuid} not found"})
    return _json_resource(found["body"])


def resource_schema(object_type: str) -> str:
    ensure_initialised()
    schemas = OpenTide.JsonSchemas.Index
    key = _resolve_family_key(schemas, object_type)
    if key is None:
        return _json_resource(
            {
                "error": f"No JSON Schema generated for {object_type!r}",
                "available": sorted(str(name) for name in schemas),
                "hint": "run 'opentide generate schemas'",
            }
        )
    return _json_resource(schemas[key])


def resource_template(object_type: str) -> str:
    ensure_initialised()
    templates = OpenTide.Templates.Index
    key = _resolve_family_key(templates, object_type)
    if key is None:
        return _json_resource(
            {
                "error": f"No template available for {object_type!r}",
                "available": sorted(str(name) for name in templates),
            }
        )
    return _json_resource(templates[key])


def resource_vocabularies() -> str:
    ensure_initialised()
    return _json_resource(OpenTide.Vocabularies.Index)


def resource_vocabulary(name: str) -> str:
    ensure_initialised()
    vocabularies = OpenTide.Vocabularies.Index
    if name in vocabularies:
        return _json_resource(vocabularies[name])
    return _json_resource(
        {
            "error": f"Unknown vocabulary {name!r}",
            "available": sorted(str(key) for key in vocabularies),
        }
    )


def resource_platforms() -> str:
    ensure_initialised()
    platforms = [
        {
            "name": name,
            "enabled": plat.enabled,
            "can_deploy": plat.can_deploy,
            "can_validate": plat.can_validate,
        }
        for name, plat in OpenTide.Platforms.items()
    ]
    return _json_resource(platforms)
