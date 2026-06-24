"""Load Tide objects by metadata.schema identifier."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from opentide.models.base import TideModel
from opentide.models.migration import stamp_schema_identifier
from opentide.models.schema_registry import core_object_schemas, get_chain, resolve_model
from opentide.models.version import SchemaVersion


def schema_id_from_body(body: dict[str, Any]) -> str:
    """Extract schema identifier from object YAML body."""
    metadata = body.get("metadata") or body.get("meta") or {}
    schema_id = metadata.get("schema")
    if not schema_id:
        raise ValueError("missing metadata.schema on object")
    return str(schema_id)


def _maybe_migrate_body(
    body: dict[str, Any],
    *,
    source_id: str,
    target_id: str,
) -> dict[str, Any]:
    if source_id == target_id:
        return body
    source = SchemaVersion.parse(source_id)
    target = SchemaVersion.parse(target_id)
    if source.family != target.family:
        raise ValueError(f"cannot migrate across families: {source_id!r} -> {target_id!r}")
    return get_chain(source.family).migrate(body, source, target)


def _instantiate_model(
    model_cls: type[TideModel],
    body: dict[str, Any],
    *,
    file: Path | None = None,
) -> TideModel:
    loader = getattr(model_cls, "from_yaml_dict", None)
    if loader is not None:
        from_yaml = cast(Callable[..., TideModel], loader)
        if file is not None:
            return from_yaml(body, file=file)
        return from_yaml(body)
    return model_cls.model_validate(body)


def load_object(
    body: dict[str, Any],
    *,
    file: Path | None = None,
    target_schema: str | None = None,
) -> TideModel:
    """Parse YAML dict into typed model using metadata.schema routing."""
    schema_id = schema_id_from_body(body)
    target_id = target_schema or schema_id
    model_cls = resolve_model(target_id)
    resolved_id = model_cls.schema_identifier()
    migrated = _maybe_migrate_body(body, source_id=schema_id, target_id=resolved_id)
    if schema_id != resolved_id:
        migrated = stamp_schema_identifier(migrated, resolved_id)
    return _instantiate_model(model_cls, migrated, file=file)


def load_object_by_type(
    body: dict[str, Any],
    object_type: str,
    *,
    file: Path | None = None,
) -> TideModel:
    """Fallback: load by index object_type when schema missing (legacy)."""
    models = core_object_schemas()
    model_cls = models.get(object_type)
    if model_cls is None:
        raise ValueError(f"unknown object type: {object_type!r}")
    return _instantiate_model(model_cls, body, file=file)


def load_object_for_validation(
    body: dict[str, Any],
    object_type: str,
    *,
    file: Path | None = None,
) -> TideModel:
    """Validate object body via Pydantic, preferring metadata.schema routing."""
    metadata = body.get("metadata") or body.get("meta") or {}
    if metadata.get("schema"):
        return load_object(body, file=file)
    return load_object_by_type(body, object_type, file=file)
