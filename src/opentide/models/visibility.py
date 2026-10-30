"""Visibility configuration Pydantic model — replaces visibility.meta.yaml."""

from __future__ import annotations

from typing import ClassVar

from pydantic import ValidationInfo, field_validator

from opentide.models.base import TideField, TideModel

#: The dataset fields a log source may set, by the `system` that reads them.
#: A field outside its system's list is a validation error, so a Splunk index
#: never makes a Sentinel table known. The analysis engine reads the same
#: fields from the file itself (:func:`opentide.analysis.install_workspace_visibility`).
DATASET_FIELDS: dict[str, tuple[str, ...]] = {
    "sentinel": ("tables",),
    "defender_for_endpoint": ("tables",),
    "splunk": ("indexes", "sourcetypes", "macros"),
    "elastic": ("indices", "data_views", "ecs"),
}

#: Every dataset field, in the order the model declares them.
DATASET_FIELD_NAMES: tuple[str, ...] = (
    "tables",
    "indexes",
    "sourcetypes",
    "macros",
    "indices",
    "data_views",
    "ecs",
)


def systems_for(field: str) -> tuple[str, ...]:
    """The `system` values whose log sources may set *field*."""
    return tuple(system for system, fields in DATASET_FIELDS.items() if field in fields)


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
    # The dataset fields: what the query checks know a log source by. Each fits
    # the systems DATASET_FIELDS lists; `*` matches any run of characters.
    tables: list[str] | None = None
    """KQL tables and functions the logs fill (`sentinel`, `defender_for_endpoint`)."""
    indexes: list[str] | None = None
    """Splunk indexes the logs fill, as `index=` names them (`splunk`)."""
    sourcetypes: list[str] | None = None
    """Splunk sourcetypes the logs carry, as `sourcetype=` names them (`splunk`)."""
    macros: list[str] | None = None
    """Splunk macros that search the logs, without backticks (`splunk`)."""
    indices: list[str] | None = None
    """Elastic index patterns and data streams the logs fill, as `index` names them (`elastic`)."""
    data_views: list[str] | None = None
    """Elastic data view ids that cover the logs, as `data_view_id` names them (`elastic`)."""
    ecs: bool | None = None
    """Whether the `indices` follow the Elastic Common Schema (`elastic`)."""

    @field_validator(*DATASET_FIELD_NAMES)
    @classmethod
    def _fits_system(cls, value: object, info: ValidationInfo) -> object:
        """A dataset field is set only on a log source of a system that reads it."""
        if value is None or info.field_name is None:
            return value
        system = info.data.get("system")
        if not isinstance(system, str):
            # `system` failed validation itself: that error is the one to read.
            return value
        if info.field_name not in DATASET_FIELDS.get(system, ()):
            fits = ", ".join(systems_for(info.field_name))
            raise ValueError(
                f"`{info.field_name}` does not apply to system {system!r}; "
                f"it applies to a log source of {fits}"
            )
        if isinstance(value, list) and any(not name.strip() for name in value):
            raise ValueError(f"`{info.field_name}` holds an empty name")
        return value


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

    def unknown_assets(self) -> list[tuple[str, int, str, int, str]]:
        """Asset names a log source or detector uses that `[[assets]]` does not declare.

        Each is `(table, index, entry name, position, asset)`, with `table`
        `"logsources"` or `"detectors"`.
        """
        known = {asset.name for asset in self.assets or []}
        found: list[tuple[str, int, str, int, str]] = []
        tables: tuple[tuple[str, list[VisibilityLogSource] | list[VisibilityDetector]], ...] = (
            ("logsources", self.logsources or []),
            ("detectors", self.detectors or []),
        )
        for table, items in tables:
            for index, item in enumerate(items):
                for position, asset in enumerate(item.assets or []):
                    if asset not in known:
                        found.append((table, index, item.name, position, asset))
        return found
