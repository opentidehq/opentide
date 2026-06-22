"""Shared metadata models for Tide objects."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from opentide.models.base import TideModel


class Organisation(TideModel):
    uuid: str
    name: str


class ObjectMetadata(TideModel):
    uuid: str
    schema_id: str = Field(alias="schema")
    version: str | int
    created: str
    modified: str
    tlp: str
    author: str | None = None
    contributors: list[str] | None = None
    organisation: Organisation | None = None

    @field_validator("created", "modified", mode="before")
    @classmethod
    def _coerce_dates(cls, value: Any) -> str:
        if hasattr(value, "isoformat"):
            return str(value)
        return str(value)


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
