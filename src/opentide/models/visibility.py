"""Visibility configuration Pydantic model — replaces visibility.meta.yaml."""

from __future__ import annotations

from typing import ClassVar

from opentide.models.base import TideField, TideModel


class VisibilityAsset(TideModel):
    """One `[[assets]]` entry: a system in the environment that generates logs."""

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
    """One `[[logsources]]` entry: a log source a rule's signals can name."""

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
    """One `[[detectors]]` entry: an external detector an objective can name."""

    name: str
    """Detector name."""
    description: str
    """What the detector covers."""
    references: list[str] | None = None
    """Reference links."""
    assets: list[str] | None = None
    """Names of the assets the detector monitors."""


# ``logsources`` and ``detectors`` declare the objects themselves, so they
# carry no ``tide.config.visibility.*`` marker: that marker fills a field with
# the configured names, and on these lists it replaced the object schema of
# every item with a string enum. The docstring below is the schema's hover text.
class VisibilityConfig(TideModel):
    """Merged `visibility.toml`: the assets, log sources and external detectors in use."""

    __schema_identifier__: ClassVar[str] = "visibility::1.0"

    assets: list[VisibilityAsset] | None = TideField(
        default=None,
        schema_extra={"title": "Assets"},
    )
    """Assets that generate logs in the environment."""
    logsources: list[VisibilityLogSource] = TideField(
        ...,
        schema_extra={"title": "Log Sources"},
    )
    """Log sources available to detection signals."""
    detectors: list[VisibilityDetector] | None = TideField(
        default=None,
        schema_extra={"title": "External Detectors"},
    )
    """External detectors that already cover parts of the environment."""
