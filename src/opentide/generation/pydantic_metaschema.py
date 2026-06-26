"""Build metaschema-compatible dicts from Pydantic Tide models."""

from __future__ import annotations

from typing import Any, cast

from opentide.generation.model_json_schema import model_json_schema
from opentide.models.base import TideModel, field_json_schema_extra
from opentide.models.metadata import ObjectMetadata, ObjectReferences
from opentide.models.object_types import OBJECTIVE, RULE, THREAT
from opentide.models.schema_registry import core_object_schemas, resolve_model
from opentide.models.version import SchemaVersion


def core_schema_models() -> dict[str, type[TideModel]]:
    """Latest registered model per core object family (rule, threat, objective)."""
    return core_object_schemas()


DEFINITION_MODELS: dict[str, type[TideModel]] = {
    "metadata": ObjectMetadata,
    "references": ObjectReferences,
}

_CORE_ROOT_EXTRAS_BASE: dict[str, dict[str, Any]] = {
    RULE: {
        "title": "Detection Rule Schema",
        "description": "A detection rule defines how a detection opportunity is implemented.",
        "additionalProperties": False,
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
                "tide.template.config.default": "schema.templates.rule::description",
            },
            "detection_model": {"tide.vocab": OBJECTIVE},
            "references": {"tide.meta.definition": True},
            "configurations": {
                "title": "Detection System Technical Setup",
                "recomposition": "systems",
            },
        },
    },
    OBJECTIVE: {
        "title": "Detection Objective Schema",
        "additionalProperties": False,
        "required": ["name", "metadata", "objective", "composition"],
        "tide.template.force-required": ["metadata"],
        "property_extras": {
            "metadata": {"tide.template.spacer": True, "tide.meta.definition": True},
            "references": {"tide.meta.definition": True},
        },
    },
    THREAT: {
        "title": "Threat Vector Schema",
        "additionalProperties": False,
        "required": ["name", "criticality", "metadata", "threat"],
        "tide.template.force-required": ["metadata"],
        "property_extras": {
            "metadata": {"tide.template.spacer": True, "tide.meta.definition": True},
            "references": {"tide.meta.definition": True},
        },
    },
}


def _core_root_extras_for_model(model: type[TideModel], family: str) -> dict[str, Any]:
    base = dict(_CORE_ROOT_EXTRAS_BASE.get(family, {}))
    base["tide.placeholders"] = {"SCHEMA_VERSION": model.schema_identifier()}
    return base


def _core_root_extras() -> dict[str, dict[str, Any]]:
    extras: dict[str, dict[str, Any]] = {}
    for key, model in core_schema_models().items():
        extras[key] = _core_root_extras_for_model(model, key)
    return extras


CORE_ROOT_EXTRAS = _core_root_extras()


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
    defs = cast(dict[str, Any], raw.get("$defs", {}))
    _merge_model_field_extras(model, properties)
    _merge_nested_def_extras(model, defs)

    if root_extras:
        property_extras = root_extras.pop("property_extras", {})
        _apply_nested_property_extras(properties, property_extras)

    result: dict[str, Any] = {"type": "object", "properties": properties}
    if defs:
        result["$defs"] = defs
    if "required" in raw:
        result["required"] = raw["required"]
    for key, value in (root_extras or {}).items():
        if key != "property_extras":
            result[key] = value
    return result


def build_core_schema_source(model_key: str) -> dict[str, Any]:
    """Build template/schema source for a core object family (latest registered model)."""
    model = core_schema_models()[model_key]
    extras = _core_root_extras_for_model(model, model_key)
    return build_model_schema_source(model, root_extras=extras)


def build_schema_source_for_identifier(schema_id: str) -> dict[str, Any]:
    """Build metaschema source for a specific registered schema identifier."""
    model = resolve_model(schema_id)
    family = SchemaVersion.parse(schema_id).family
    extras = _core_root_extras_for_model(model, family)
    result = build_model_schema_source(model, root_extras=extras)
    apply_vocab_pins(result, schema_id)
    return result


def apply_vocab_pins(schema: dict[str, Any], schema_id: str) -> None:
    """Inject versioned ``tide.vocab`` contracts from the pin manifest onto *schema*."""
    from opentide.models.vocab_pins import get_pins

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    defs = schema.get("$defs", {})
    defs_map = defs if isinstance(defs, dict) else {}
    for dot_path, contract in get_pins(schema_id).items():
        parts = [part for part in dot_path.split(".") if part]
        if parts:
            _set_vocab_at_path(properties, parts, contract, defs=defs_map)


def _set_vocab_at_path(
    node: dict[str, Any],
    parts: list[str],
    contract: str,
    *,
    defs: dict[str, Any],
) -> None:
    if not parts:
        return
    key = parts[0]
    if key not in node or not isinstance(node[key], dict):
        return
    field_schema = node[key]
    if "$ref" in field_schema and len(parts) > 1:
        ref_name = str(field_schema["$ref"]).rsplit("/", 1)[-1]
        target = defs.get(ref_name)
        if isinstance(target, dict):
            nested_props = target.setdefault("properties", {})
            if isinstance(nested_props, dict):
                _set_vocab_at_path(nested_props, parts[1:], contract, defs=defs)
        return
    if len(parts) == 1:
        field_schema["tide.vocab"] = contract
        return

    if field_schema.get("type") == "array":
        items = field_schema.get("items")
        if isinstance(items, dict):
            item_props = items.setdefault("properties", {})
            if isinstance(item_props, dict):
                _set_vocab_at_path(item_props, parts[1:], contract, defs=defs)
        return

    nested_props = field_schema.get("properties")
    if isinstance(nested_props, dict):
        _set_vocab_at_path(nested_props, parts[1:], contract, defs=defs)


def _merge_nested_def_extras(model: type[TideModel], defs: dict[str, Any]) -> None:
    """Merge Tide field extras into ``$defs`` entries for nested models."""
    for field in model.model_fields.values():
        nested = _resolve_model_type(field.annotation)
        if not nested:
            continue
        def_schema = defs.get(nested.__name__)
        if not isinstance(def_schema, dict):
            continue
        nested_props = def_schema.get("properties")
        if isinstance(nested_props, dict):
            _merge_model_field_extras(nested, nested_props)
            _merge_nested_def_extras(nested, defs)


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
