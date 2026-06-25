"""MCP resource providers."""

from __future__ import annotations

from typing import Any

from opentide.core.io import dump_json_text
from opentide.core.registry import OpenTide
from opentide.mcp_server.catalog import ensure_initialised, get_object


def _json_resource(payload: Any) -> str:
    return dump_json_text(payload, indent=True, default=str)


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
    key = {"rule": "rule", "threat": "threat", "objective": "objective"}.get(
        object_type, object_type
    )
    return _json_resource(schemas.get(key, {}))


def resource_template(object_type: str) -> str:
    ensure_initialised()
    templates = OpenTide.Templates.Index
    key = {"rule": "rule", "threat": "threat", "objective": "objective"}.get(
        object_type, object_type
    )
    return _json_resource(templates.get(key, {}))


def resource_vocabularies() -> str:
    ensure_initialised()
    return _json_resource(OpenTide.Vocabularies.Index)


def resource_vocabulary(name: str) -> str:
    ensure_initialised()
    return _json_resource(OpenTide.Vocabularies.Index.get(name, {}))


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
