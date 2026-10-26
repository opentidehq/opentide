"""Visibility configuration Pydantic model — replaces visibility.meta.yaml."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from opentide.models.base import TideField, TideModel


class VisibilityAsset(TideModel):
    """One `[[assets]]` entry: a system in the environment that generates logs."""

    name: str = Field(description="Asset name that log sources and detectors refer to.")
    description: str = Field(description="What the asset is.")
    criticality: str = Field(description="How critical the asset is to the organisation.")
    custom_details: dict[str, str | bool | int | float] | None = Field(
        default=None, description="Free-form details shown with the asset."
    )
    surface: list[str] | None = Field(default=None, description="Technologies the asset exposes.")


class VisibilityLogSource(TideModel):
    """One `[[logsources]]` entry: a log source a rule's signals can name."""

    name: str = Field(description="Log source name a signal refers to.")
    description: str = Field(description="What the log source collects.")
    system: str = Field(description="Platform identifier the log source is searched on.")
    assets: list[str] | None = Field(
        default=None, description="Names of the [[assets]] the log source collects from."
    )
    tenants: list[str] | None = Field(
        default=None, description="Tenants of the platform the log source is available on."
    )
    references: list[str] | None = Field(default=None, description="Reference links.")


class VisibilityDetector(TideModel):
    """One `[[detectors]]` entry: an external detector an objective can name."""

    name: str = Field(description="Detector name an objective refers to.")
    description: str = Field(description="What the detector detects.")
    references: list[str] | None = Field(default=None, description="Reference links.")
    assets: list[str] | None = Field(
        default=None, description="Names of the [[assets]] the detector covers."
    )


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
        description="Log sources available in the environment",
    )
    detectors: list[VisibilityDetector] | None = TideField(
        default=None,
        schema_extra={"title": "External Detectors"},
        description="Detectors outside opentide that cover the environment",
    )
