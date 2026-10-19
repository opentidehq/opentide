"""Load Tide objects by metadata.schema identifier."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from opentide.models.base import TideModel
from opentide.models.migration import stamp_schema_identifier
from opentide.models.schema_registry import get_chain, resolve_model
from opentide.models.version import SchemaVersion


class SchemaMissingError(ValueError):
    """An object declares no ``metadata.schema``, so no model can check it."""

    code = "schema_missing"


class SchemaIdentifierError(LookupError):
    """``metadata.schema`` names no registered revision of the expected object type."""

    code = "schema_validation"


def schema_id_from_body(body: dict[str, Any]) -> str:
    """Extract schema identifier from object YAML body."""
    metadata = body.get("metadata") or body.get("meta") or {}
    schema_id = metadata.get("schema") if isinstance(metadata, dict) else None
    if not schema_id:
        raise SchemaMissingError("missing metadata.schema on object")
    return str(schema_id)


def resolve_family_model(schema_id: str, family: str) -> type[TideModel]:
    """Return the model for *schema_id*, which must be a revision of *family*.

    Raises ``SchemaIdentifierError`` (a ``LookupError``) for an unregistered
    identifier or one of another family. Neither falls back to the family's
    newest revision (versioning 1.1).
    """
    try:
        model_cls = resolve_model(schema_id)
    except LookupError as exc:
        raise SchemaIdentifierError(str(exc)) from exc
    if SchemaVersion.parse(schema_id).family != family:
        raise SchemaIdentifierError(f"{schema_id!r} is not a {family} schema identifier")
    return model_cls


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


def load_object_for_validation(
    body: dict[str, Any],
    object_type: str,
    *,
    file: Path | None = None,
) -> TideModel:
    """Check *body* against the *object_type* revision its ``metadata.schema`` names.

    Raises ``SchemaMissingError`` when the identifier is absent and
    ``SchemaIdentifierError`` when it is unknown or of another family.
    """
    model_cls = resolve_family_model(schema_id_from_body(body), object_type)
    return _instantiate_model(model_cls, body, file=file)
