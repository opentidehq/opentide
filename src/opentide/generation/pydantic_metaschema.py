"""Build metaschema-compatible dicts from Pydantic Tide models."""

from __future__ import annotations

from typing import Any, cast

from opentide.generation.schema import model_json_schema
from opentide.models.base import TideModel, field_json_schema_extra
from opentide.models.metadata import ObjectMetadata, ObjectReferences
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector

CORE_SCHEMA_MODELS: dict[str, type[TideModel]] = {
    "mdr": DetectionRule,
    "dom": DetectionObjective,
    "tvm": ThreatVector,
}

DEFINITION_MODELS: dict[str, type[TideModel]] = {
    "metadata": ObjectMetadata,
    "references": ObjectReferences,
}

CORE_ROOT_EXTRAS: dict[str, dict[str, Any]] = {
    "mdr": {
        "title": "MDR Schema validator",
        "description": "A Managed Detection Rule is ...",
        "additionalProperties": False,
        "tide.placeholders": {"SCHEMA_VERSION": "mdr::2.1"},
        "required": ["name", "response", "description", "configurations"],
        "tide.template.force-required": ["metadata"],
        "anyOf": [{"required": ["metadata"]}, {"required": ["meta"]}],
        "property_extras": {
            "metadata": {"tide.template.spacer": True, "tide.meta.definition": True},
            "meta": {
                "tide.template.hide": True,
                "tide.meta.deprecation": "Use metadata keyword instead",
                "tide.meta.definition": "metadata",
            },
            "description": {
                "tide.template.spacer": True,
                "tide.template.multiline": True,
                "tide.template.config.default": "schema.templates.mdr::description",
            },
            "detection_model": {"tide.vocab": "dom"},
            "references": {"tide.meta.definition": True},
            "configurations": {
                "title": "Detection System Technical Setup",
                "recomposition": "systems",
            },
        },
    },
    "dom": {
        "title": "Detection Objective Schema",
        "additionalProperties": False,
        "tide.placeholders": {"SCHEMA_VERSION": "dom::2.0"},
        "required": ["name", "metadata", "objective", "composition"],
        "tide.template.force-required": ["metadata"],
        "property_extras": {
            "metadata": {"tide.template.spacer": True, "tide.meta.definition": True},
            "references": {"tide.meta.definition": True},
        },
    },
    "tvm": {
        "title": "Threat Vector Schema",
        "additionalProperties": False,
        "tide.placeholders": {"SCHEMA_VERSION": "tvm::2.0"},
        "required": ["name", "criticality", "metadata", "threat"],
        "tide.template.force-required": ["metadata"],
        "property_extras": {
            "metadata": {"tide.template.spacer": True, "tide.meta.definition": True},
            "references": {"tide.meta.definition": True},
        },
    },
}


def build_definition_index() -> dict[str, dict[str, Any]]:
    """Generate definition schemas from registered Pydantic models."""
    definitions: dict[str, dict[str, Any]] = {}
    for name, model in DEFINITION_MODELS.items():
        definitions[name] = build_model_schema_source(model)
    return definitions


def build_model_schema_source(
    model: type[TideModel],
    *,
    root_extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a metaschema-compatible dict from a Pydantic model."""
    raw = model_json_schema(model)
    properties = cast(dict[str, Any], raw.get("properties", {}))
    _merge_model_field_extras(model, properties)

    if root_extras:
        property_extras = root_extras.pop("property_extras", {})
        _apply_nested_property_extras(properties, property_extras)

    result: dict[str, Any] = {"type": "object", "properties": properties}
    if "required" in raw:
        result["required"] = raw["required"]
    for key, value in (root_extras or {}).items():
        if key != "property_extras":
            result[key] = value
    return result


def build_core_schema_source(model_key: str) -> dict[str, Any]:
    """Build template/schema source for a core object model key."""
    model = CORE_SCHEMA_MODELS[model_key]
    extras = dict(CORE_ROOT_EXTRAS.get(model_key, {}))
    return build_model_schema_source(model, root_extras=extras)


def build_platform_schema_source(model: type[TideModel]) -> dict[str, Any]:
    """Build template/schema source for a platform configuration model."""
    from opentide.models.platform_schema import platform_root_extras

    extras = platform_root_extras(model)
    return build_model_schema_source(model, root_extras=extras)


def _apply_nested_property_extras(
    properties: dict[str, Any],
    extras: dict[str, Any],
) -> None:
    for field_name, field_extras in extras.items():
        if field_name not in properties:
            continue
        nested = field_extras.pop("properties", None)
        items = field_extras.pop("items", None)
        properties[field_name].update(field_extras)
        if nested:
            child_props = properties[field_name].setdefault("properties", {})
            if isinstance(child_props, dict):
                _apply_nested_property_extras(child_props, nested)
        if items and isinstance(items, dict):
            item_props = properties[field_name].setdefault("items", {}).get("properties")
            if isinstance(item_props, dict) and "properties" in items:
                _apply_nested_property_extras(item_props, items["properties"])


def _merge_model_field_extras(model: type[TideModel], properties: dict[str, Any]) -> None:
    for name, field in model.model_fields.items():
        extras = field_json_schema_extra(field)
        if name in properties and extras:
            properties[name].update(extras)
        annotation = field.annotation
        nested = _resolve_model_type(annotation)
        if nested and name in properties:
            nested_props = properties[name].get("properties")
            if isinstance(nested_props, dict):
                _merge_model_field_extras(nested, nested_props)
            items = properties[name].get("items")
            if isinstance(items, dict):
                item_props = items.get("properties")
                if isinstance(item_props, dict):
                    _merge_model_field_extras(nested, item_props)


def _resolve_model_type(annotation: Any) -> type[TideModel] | None:
    origin = getattr(annotation, "__origin__", None)
    if origin is list:
        args = getattr(annotation, "__args__", ())
        if args:
            annotation = args[0]
    if isinstance(annotation, type) and issubclass(annotation, TideModel):
        return annotation
    return None


def _normalize_schema(schema: dict[str, Any]) -> dict[str, Any]:
    if "properties" not in schema:
        return {"properties": schema}
    return schema


def lookup_schema_extra(
    schema: dict[str, Any],
    field: str,
    key: str,
    *,
    scope: str | None = None,
) -> Any:
    """Retrieve Tide metadata from a generated schema dict (replaces get_value_metaschema)."""
    schema = _normalize_schema(schema)
    properties = schema.get("properties", {})
    if scope:
        scoped = lookup_schema_extra(schema, scope, "tide.meta")
        if scope == "threat_objects" and isinstance(scoped, dict):
            scoped_props = scoped.get(field, scoped)
            if isinstance(scoped_props, dict) and key in scoped_props:
                return scoped_props.get(key)
            if isinstance(scoped, dict):
                items = scoped.get("items", {})
                if isinstance(items, dict):
                    item_props = items.get("properties", {})
                    if field in item_props:
                        return item_props[field].get(key)
        if isinstance(scoped, dict) and field in scoped:
            field_schema = scoped[field]
            if isinstance(field_schema, dict):
                return field_schema.get(key)
            if key == "tide.meta":
                return {field: field_schema}

    if field in properties:
        field_schema = properties[field]
        if key == "tide.meta":
            return {field: field_schema}
        if isinstance(field_schema, dict):
            if key in field_schema:
                return field_schema[key]
            nested_props = field_schema.get("properties")
            if isinstance(nested_props, dict):
                result = lookup_schema_extra({"properties": nested_props}, field, key, scope=scope)
                if result is not None:
                    return result

    for prop_schema in properties.values():
        if not isinstance(prop_schema, dict):
            continue
        if prop_schema.get("type") == "object" and "recomposition" not in prop_schema:
            nested = prop_schema.get("properties")
            if isinstance(nested, dict):
                result = lookup_schema_extra({"properties": nested}, field, key, scope=scope)
                if result is not None:
                    return result
        items = prop_schema.get("items")
        if isinstance(items, dict):
            item_props = items.get("properties")
            if isinstance(item_props, dict):
                result = lookup_schema_extra({"properties": item_props}, field, key, scope=scope)
                if result is not None:
                    return result
    return None


def platform_field_extra(
    model: type[TideModel],
    field: str,
    key: str,
    *,
    scope: str | None = None,
) -> Any:
    """Look up platform field metadata from a Pydantic model schema."""
    schema = build_platform_schema_source(model)
    return lookup_schema_extra(schema, field, key, scope=scope)
