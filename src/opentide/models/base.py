"""Pydantic base types for code-first OpenTide models."""

from __future__ import annotations

from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field
from pydantic.fields import FieldInfo


def TideField(
    default: Any = ..., *, schema_extra: dict[str, Any] | None = None, **kwargs: Any
) -> Any:
    """Field helper carrying Tide JSON Schema / template metadata."""
    json_schema_extra = dict(schema_extra or {})
    return Field(default, json_schema_extra=json_schema_extra, **kwargs)


def VocabField(
    vocab: str | bool = True,
    default: Any = ...,
    **kwargs: Any,
) -> Any:
    """Field marked as vocabulary-constrained in generated metaschema."""
    return TideField(default, schema_extra={"tide.vocab": vocab}, **kwargs)


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
