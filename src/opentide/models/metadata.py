"""Shared metadata models for Tide objects."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from opentide.models.base import TideField, TideModel, VocabField
from opentide.models.review import parse_review_instant


class Organisation(TideModel):
    uuid: str
    """Organisation UUID. Sharing uses it as the default publishing organisation."""
    name: str
    """Organisation display name."""


class ObjectMetadata(TideModel):
    uuid: str
    """Globally unique object identifier."""
    schema_id: str = Field(alias="schema")
    """Schema identifier, for example `rule::1.0`. Selects the revision schema that validates this
    object."""
    version: str | int
    """Business version of this instance."""
    created: str = TideField(schema_extra={"format": "date"})
    """Creation date."""
    modified: str = TideField(schema_extra={"format": "date"})
    """Last modification date."""
    tlp: str = VocabField(True)
    """Traffic Light Protocol classification."""
    author: str | None = None
    """Primary author."""
    contributors: list[str] | None = None
    """Additional contributors."""
    organisation: Organisation | None = None
    """Owning organisation."""

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


_SPACED_DATETIME = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"


class RuleMetadata(ObjectMetadata):
    """``rule::1.1`` metadata: optional ISO 8601 ``reviewed`` instant."""

    # Editor schema mirrors parse_review_instant: an ISO 8601 date or a datetime
    # with an offset, including the space-separated form the parser accepts.
    reviewed: str | None = TideField(
        None,
        schema_extra={
            "anyOf": [
                {"type": "string", "format": "date"},
                {"type": "string", "format": "date-time"},
                {"type": "string", "pattern": _SPACED_DATETIME},
                {"type": "null"},
            ]
        },
    )
    """Last human review of this rule, as an ISO 8601 date or datetime. Omitted means no recorded
    review."""

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
    """Public reference IDs to URLs (YAML int keys coerced on load)."""
    internal: dict[str, str] | None = None
    """Internal reference keys to URLs."""
    reports: list[str] | None = None
    """Report links."""

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
