"""Visibility configuration Pydantic model — replaces visibility.meta.yaml."""

from __future__ import annotations

from typing import ClassVar

from opentide.models.base import TideField, TideModel


class VisibilityAsset(TideModel):
    name: str
    description: str
    criticality: str
    custom_details: dict[str, str | bool | int | float] | None = None
    surface: list[str] | None = None


class VisibilityLogSource(TideModel):
    name: str
    description: str
    system: str
    assets: list[str] | None = None
    tenants: list[str] | None = None
    references: list[str] | None = None


class VisibilityDetector(TideModel):
    name: str
    description: str
    references: list[str] | None = None
    assets: list[str] | None = None


class VisibilityConfig(TideModel):
    """Code-first visibility configuration schema.

    ``logsources`` and ``detectors`` declare the objects themselves, so they
    carry no ``tide.config.visibility.*`` marker: that marker fills a field with
    the configured names, and on these lists it replaced the object schema of
    every item with a string enum.
    """

    __schema_identifier__: ClassVar[str] = "visibility::1.0"

    assets: list[VisibilityAsset] | None = TideField(
        default=None,
        schema_extra={
            "title": "Assets",
            "description": "List of assets that generate logs in the environment",
        },
    )
    logsources: list[VisibilityLogSource] = TideField(
        ...,
        schema_extra={"title": "Log Sources"},
    )
    detectors: list[VisibilityDetector] | None = TideField(
        default=None,
        schema_extra={"title": "External Detectors"},
    )
