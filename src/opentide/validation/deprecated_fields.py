"""Deprecated field warnings from metaschema ``tide.meta.deprecation`` markers."""

from __future__ import annotations

from typing import Any

from opentide.models.version import SchemaVersion
from opentide.validation.issues import ValidationIssue


def resolve_metaschema(
    metaschemas: dict[str, Any],
    payload: dict[str, Any],
    object_type: str,
) -> dict[str, Any] | None:
    """Pick the metaschema for *payload*, preferring ``metadata.schema``."""
    metadata = payload.get("metadata") or payload.get("meta") or {}
    schema_id = metadata.get("schema")
    if isinstance(schema_id, str) and schema_id in metaschemas:
        return metaschemas[schema_id]
    family_matches = [
        (key, value)
        for key, value in metaschemas.items()
        if isinstance(key, str) and "::" in key and SchemaVersion.parse(key).family == object_type
    ]
    if not family_matches:
        legacy = metaschemas.get(object_type)
        return legacy if isinstance(legacy, dict) else None
    latest_key = max(family_matches, key=lambda item: SchemaVersion.parse(item[0]).sort_key())[0]
    schema = metaschemas.get(latest_key)
    return schema if isinstance(schema, dict) else None


def walk_deprecated_fields(
    payload: dict[str, Any],
    schema: dict[str, Any],
    *,
    object_uuid: str = "",
    object_type: str = "",
    path: tuple[str, ...] = (),
) -> list[ValidationIssue]:
    """Emit warnings when deprecated metaschema fields are present on the payload."""
    issues: list[ValidationIssue] = []
    properties = schema.get("properties", schema)
    if not isinstance(properties, dict):
        return issues

    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, dict):
            continue
        field_path = (*path, field_name)
        value = _get_nested(payload, field_path)
        deprecation = field_schema.get("tide.meta.deprecation")
        if deprecation and value is not None:
            issues.append(
                ValidationIssue(
                    code="deprecated_field",
                    severity="warning",
                    object_uuid=object_uuid,
                    object_type=object_type,
                    field_path=field_path,
                    message=f"Field {'.'.join(field_path)!r} is deprecated: {deprecation}",
                    context={"deprecation": str(deprecation)},
                )
            )
        nested_props = field_schema.get("properties")
        if isinstance(nested_props, dict) and isinstance(value, dict):
            issues.extend(
                walk_deprecated_fields(
                    value,
                    field_schema,
                    object_uuid=object_uuid,
                    object_type=object_type,
                    path=field_path,
                )
            )
    return issues


def validate_deprecated_fields_from_metaschema(
    payload: dict[str, Any],
    metaschemas: dict[str, Any],
    object_type: str,
    *,
    object_uuid: str = "",
) -> list[ValidationIssue]:
    schema = resolve_metaschema(metaschemas, payload, object_type)
    if not schema:
        return []
    return walk_deprecated_fields(
        payload,
        schema,
        object_uuid=object_uuid,
        object_type=object_type,
    )


def _get_nested(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    node: Any = data
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node
