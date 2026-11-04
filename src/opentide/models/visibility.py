"""Visibility configuration Pydantic model (``visibility::1.0``).

A `[[logsources]]` entry is one dataset, and its `name` is that dataset: the
KQL table (or workspace function) for `sentinel` and `defender_for_endpoint`,
the sourcetype for `splunk`, the index pattern or data stream for `elastic`.
It may list the dataset's columns, keyed by column name. The query checks of
the analysis engine read the same file themselves
(:func:`opentide.analysis.install_workspace_visibility`).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from pydantic import ValidationError, ValidationInfo, field_validator, model_validator
from pydantic_core import InitErrorDetails, PydanticCustomError

from opentide.models.base import TideField, TideModel

#: What a log source's `name` declares to the query checks, by `system`.
#: A system that is not listed declares nothing.
DATASET_KINDS: dict[str, str] = {
    "sentinel": "KQL table",
    "defender_for_endpoint": "KQL table",
    "splunk": "sourcetype",
    "elastic": "index pattern",
}

#: The opentide 0.20.0 dataset keys, which `visibility::1.0` does not accept,
#: and the message each fails with: what to do instead.
LEGACY_DATASET_KEYS: dict[str, str] = {
    "tables": "`tables` was removed in 0.20.1: declare each table as its own [[logsources]] "
    "entry whose `name` is the table",
    "sourcetypes": "`sourcetypes` was removed in 0.20.1: declare each sourcetype as its own "
    "[[logsources]] entry whose `name` is the sourcetype",
    "indices": "`indices` was removed in 0.20.1: declare each index pattern as its own "
    "[[logsources]] entry whose `name` is the index pattern",
    "indexes": "`indexes` is no longer supported (Splunk indexes are not declared); remove it",
    "macros": "`macros` is no longer supported (Splunk macros are not declared); remove it",
    "data_views": "`data_views` is no longer supported (Elastic data views are not declared); "
    "remove it",
    "ecs": "`ecs` is no longer supported; remove it",
}

#: The column types each system takes in a log source's `columns`.
COLUMN_TYPES: dict[str, tuple[str, ...]] = {
    "sentinel": (
        "bool",
        "datetime",
        "decimal",
        "dynamic",
        "guid",
        "int",
        "long",
        "real",
        "string",
        "timespan",
    ),
    "splunk": ("string", "number", "boolean"),
    "elastic": (
        "binary",
        "boolean",
        "byte",
        "constant_keyword",
        "date",
        "date_nanos",
        "double",
        "flattened",
        "float",
        "geo_point",
        "half_float",
        "integer",
        "ip",
        "keyword",
        "long",
        "match_only_text",
        "nested",
        "object",
        "scaled_float",
        "short",
        "text",
        "unsigned_long",
        "version",
        "wildcard",
    ),
}
COLUMN_TYPES["defender_for_endpoint"] = COLUMN_TYPES["sentinel"]


def _error(loc: tuple[str | int, ...], message: str) -> InitErrorDetails:
    """One `value_error` at *loc*, with *message* as written."""
    return InitErrorDetails(
        type=PydanticCustomError("value_error", "{message}", {"message": message}),
        loc=loc,
        input=None,
    )


def _invalid(message: str) -> PydanticCustomError:
    """A `value_error` with *message* as written (no "Value error, " prefix)."""
    return PydanticCustomError("value_error", "{message}", {"message": message})


class VisibilityAsset(TideModel):
    """One `[[assets]]` entry: a system in the environment that generates logs."""

    name: str
    """Asset name, referenced by log sources and detectors."""
    description: str
    """What the asset is."""
    criticality: str
    """Criticality vocabulary value."""
    custom_details: dict[str, str | bool | int | float] | None = None
    """Free-form keys with string, boolean or number values."""
    surface: list[str] | None = None
    """Threat surface vocabulary values the asset exposes."""


class VisibilityColumn(TideModel):
    """One column of a log source's dataset, under `columns.<name>`."""

    type: str
    """Column type, from the system's type set."""
    description: str | None = None
    """What the column holds."""


class VisibilityLogSource(TideModel):
    """One `[[logsources]]` entry: one dataset a rule's signals can name."""

    name: str
    """The dataset: the KQL table or workspace function (`sentinel`, `defender_for_endpoint`), the
    sourcetype (`splunk`), the index pattern or data stream (`elastic`). Unique per `system`.
    Signals reference it."""
    description: str
    """What the log source records."""
    system: str
    """Platform identifier of the system that holds the logs."""
    tenants: list[str] | None = None
    """Tenants of `system` that hold the logs."""
    assets: list[str] | None = None
    """Names of the `[[assets]]` that produce the logs."""
    references: list[str] | None = None
    """Reference links."""
    columns: dict[str, VisibilityColumn] | None = None
    """The dataset's columns, keyed by column name as-is."""

    @model_validator(mode="before")
    @classmethod
    def _no_legacy_keys(cls, data: Any) -> Any:
        """The 0.20.0 dataset keys fail on their key, saying what to do instead."""
        if not isinstance(data, Mapping):
            return data
        errors = [
            _error((key,), LEGACY_DATASET_KEYS[key]) for key in data if key in LEGACY_DATASET_KEYS
        ]
        if errors:
            raise ValidationError.from_exception_data(cls.__name__, errors)
        return data

    @field_validator("name")
    @classmethod
    def _name_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise _invalid("`name` cannot be empty")
        return value

    @field_validator("columns")
    @classmethod
    def _columns_fit_system(
        cls, value: dict[str, VisibilityColumn] | None, info: ValidationInfo
    ) -> dict[str, VisibilityColumn] | None:
        """Columns take the type set of the log source's system; other systems take none."""
        if value is None:
            return value
        system = info.data.get("system")
        if not isinstance(system, str):
            # `system` failed validation itself: that error is the one to read.
            return value
        types = COLUMN_TYPES.get(system)
        if types is None:
            raise _invalid(
                f"`columns` does not apply to system {system!r}; it applies to a log source "
                f"of {', '.join(COLUMN_TYPES)}"
            )
        errors = [_error((name,), "a column name cannot be empty") for name in value if not name]
        errors += [
            _error(
                (name, "type"),
                f"column type {column.type!r} is not a {system} type; "
                f"use one of {', '.join(types)}",
            )
            for name, column in value.items()
            if column.type not in types
        ]
        if errors:
            raise ValidationError.from_exception_data(cls.__name__, errors)
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
    """Log sources available to detection signals, one dataset each."""
    detectors: list[VisibilityDetector] | None = TideField(
        default=None,
        schema_extra={"title": "External Detectors"},
    )
    """External detectors that already cover parts of the environment."""

    @model_validator(mode="after")
    def _unique_per_system(self) -> VisibilityConfig:
        """`name` is unique per `system`; the same name under two systems is fine."""
        seen: dict[tuple[str, str], int] = {}
        errors: list[InitErrorDetails] = []
        for position, source in enumerate(self.logsources):
            first = seen.setdefault((source.system, source.name), position)
            if first != position:
                errors.append(
                    _error(
                        ("logsources", position, "name"),
                        f"log source {source.name!r} is already declared for {source.system} "
                        f"by log source {first + 1}; names are unique per system",
                    )
                )
        if errors:
            raise ValidationError.from_exception_data(type(self).__name__, errors)
        return self

    def unknown_assets(self) -> list[tuple[str, int, str, int, str]]:
        """Asset names a log source or detector uses that `[[assets]]` does not declare.

        Each is `(table, index, entry name, position, asset)`, with `table`
        `"logsources"` or `"detectors"`.
        """
        known = {asset.name for asset in self.assets or []}
        found: list[tuple[str, int, str, int, str]] = []
        for index, source in enumerate(self.logsources or []):
            for position, asset in enumerate(source.assets or []):
                if asset not in known:
                    found.append(("logsources", index, source.name, position, asset))
        for index, detector in enumerate(self.detectors or []):
            for position, asset in enumerate(detector.assets or []):
                if asset not in known:
                    found.append(("detectors", index, detector.name, position, asset))
        return found
