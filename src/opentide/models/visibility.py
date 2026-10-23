"""Visibility configuration Pydantic model — replaces visibility.meta.yaml."""

from __future__ import annotations

from typing import ClassVar

from opentide.models.base import TideField, TideModel


class VisibilityAsset(TideModel):
    name: str
    """Asset name, referenced by log sources and detectors."""
    description: str
    """What the asset is."""
    criticality: str
    """Criticality vocabulary value."""
    custom_details: dict[str, str | bool | int | float] | None = None
    """Free-form key and value details."""
    surface: list[str] | None = None
    """Threat surface vocabulary values the asset exposes."""


class VisibilityLogSource(TideModel):
    name: str
    """Log source name. Signals reference it in `data.logsources`."""
    description: str
    """What the log source records."""
    system: str
    """Detection system that holds the logs."""
    assets: list[str] | None = None
    """Names of the assets that produce these logs."""
    tenants: list[str] | None = None
    """Tenants of `system` that hold the logs."""
    references: list[str] | None = None
    """Reference links."""


class VisibilityDetector(TideModel):
    name: str
    """Detector name."""
    description: str
    """What the detector covers."""
    references: list[str] | None = None
    """Reference links."""
    assets: list[str] | None = None
    """Names of the assets the detector monitors."""


class VisibilityConfig(TideModel):
    """Code-first visibility configuration schema."""

    __schema_identifier__: ClassVar[str] = "visibility::1.0"

    assets: list[VisibilityAsset] | None = TideField(
        default=None,
        schema_extra={"title": "Assets"},
    )
    """Assets that generate logs in the environment."""
    logsources: list[VisibilityLogSource] = TideField(
        ...,
        schema_extra={
            "title": "Log Sources",
            "tide.config.visibility.logsources": True,
        },
    )
    """Log sources available to detection signals."""
    detectors: list[VisibilityDetector] | None = TideField(
        default=None,
        schema_extra={
            "title": "External Detectors",
            "tide.config.visibility.detectors": True,
        },
    )
    """External detectors that already cover parts of the environment."""
