"""Pydantic base types for code-first OpenTide models."""

from __future__ import annotations

from enum import Enum
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field
from pydantic.fields import FieldInfo

#: ``json_schema_extra`` key under which a field declares its catalogue role.
FIELD_ROLE_KEY = "tide.field.role"


class FieldRole(str, Enum):
    """Catalogue role a model field plays for cross-object field extraction.

    This is the single source of truth that lets ``core.object_fields`` derive
    technique / actor / configuration extraction from the models instead of a
    hardcoded key tuple: a field tagged with a role is read for that role on
    whatever model declares it, and a renamed or new field is picked up without
    editing an extractor.
    """

    TECHNIQUES = "techniques"
    ACTORS = "actors"
    CONFIGURATIONS = "configurations"


def TideField(
    default: Any = ...,
    *,
    schema_extra: dict[str, Any] | None = None,
    role: FieldRole | None = None,
    **kwargs: Any,
) -> Any:
    """Field helper carrying Tide JSON Schema / template metadata.

    Pass ``role`` to declare the field's catalogue role (see :class:`FieldRole`);
    it is recorded under :data:`FIELD_ROLE_KEY` in ``json_schema_extra`` so that
    extraction derives from the model rather than from a key list.
    """
    json_schema_extra = dict(schema_extra or {})
    if role is not None:
        json_schema_extra[FIELD_ROLE_KEY] = role.value
    return Field(default, json_schema_extra=json_schema_extra, **kwargs)


def VocabField(
    vocab: str | bool = True,
    default: Any = ...,
    *,
    scoped: bool = False,
    role: FieldRole | None = None,
    **kwargs: Any,
) -> Any:
    """Field marked as vocabulary-constrained in generated metaschema."""
    extra: dict[str, Any] = {"tide.vocab": vocab}
    if scoped:
        extra["tide.vocab.scoped"] = True
    return TideField(default, schema_extra=extra, role=role, **kwargs)


def field_role(field: FieldInfo) -> FieldRole | None:
    """Return the :class:`FieldRole` declared on *field*, if any."""
    value = field_json_schema_extra(field).get(FIELD_ROLE_KEY)
    if value is None:
        return None
    try:
        return FieldRole(value)
    except ValueError:
        return None


class TideModel(BaseModel):
    """Base model for all code-first Tide object definitions."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", populate_by_name=True, validate_assignment=True
    )

    @classmethod
    def schema_identifier(cls) -> str:
        """Return the canonical schema identifier (e.g. ``rule::1.0``)."""
        identifier = getattr(cls, "__schema_identifier__", None)
        if not identifier:
            raise AttributeError(f"{cls.__name__} has no __schema_identifier__")
        return cast(str, identifier)


def field_json_schema_extra(field: FieldInfo) -> dict[str, Any]:
    """Return Tide-specific metadata attached to a model field."""
    extra = field.json_schema_extra
    if isinstance(extra, dict):
        return cast(dict[str, Any], extra)
    return {}
