"""Shared metadata models for Tide objects."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from opentide.models.base import TideField, TideModel, VocabField
from opentide.models.review import parse_review_instant


class Organisation(TideModel):
    uuid: str
    name: str


class ObjectMetadata(TideModel):
    uuid: str
    schema_id: str = Field(alias="schema")
    version: str | int
    created: str = TideField(schema_extra={"format": "date"})
    modified: str = TideField(schema_extra={"format": "date"})
    tlp: str = VocabField(True)
    author: str | None = None
    contributors: list[str] | None = None
    organisation: Organisation | None = None

    @property
    def schema(self) -> str:
        """The identifier under its YAML key, which would otherwise be ``BaseModel.schema``."""
        return self.schema_id

    @field_validator("schema_id")
    @classmethod
    def _validate_schema_identifier(cls, value: str) -> str:
        from opentide.models.schema_registry import is_registered

        if not is_registered(value):
            raise ValueError(f"unknown schema identifier: {value!r}")
        return value

    @field_validator("created", "modified", mode="before")
    @classmethod
    def _coerce_dates(cls, value: Any) -> str:
        if hasattr(value, "isoformat"):
            return str(value)
        return str(value)


class RuleMetadata(ObjectMetadata):
    """``rule::1.1`` metadata: optional ISO 8601 ``reviewed`` instant."""

    reviewed: str | None = TideField(None, schema_extra={"format": "date"})

    @field_validator("reviewed", mode="before")
    @classmethod
    def _coerce_reviewed(cls, value: Any) -> str | None:
        if value is None:
            return None
        if hasattr(value, "isoformat"):
            return str(value.isoformat())
        text = str(value).strip()
        return text or None

    @field_validator("reviewed")
    @classmethod
    def _validate_reviewed(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parse_review_instant(value)
        return value


class ObjectReferences(TideModel):
    public: dict[int, str] | None = None
    internal: dict[str, str] | None = None
    reports: list[str] | None = None

    @classmethod
    def coerce_public_keys(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Normalise YAML int keys to JSON-safe string keys for validation."""
        if "public" not in data or data["public"] is None:
            return data
        public = data["public"]
        if isinstance(public, dict):
            data = dict(data)
            data["public"] = {int(key): value for key, value in public.items()}
        return data
