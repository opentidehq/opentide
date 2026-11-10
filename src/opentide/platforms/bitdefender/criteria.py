"""The GravityZone criteria catalogue (bitdefender-1.0, Criteria catalogue).

``opentide/data/bitdefender/criteria.toml`` is a verbatim copy of
opentidehq/language-server's ``catalogs/bitdefender/criteria.toml``, the one data
source for fields, enum values, relations, sensors and pairing rules, so
``opentide validate`` and the editor check a block alike.
``scripts/build/check_bitdefender_catalogue.py`` fails when the copy differs
from the one in the pinned engine. The catalogue is facts read from
Bitdefender's "Detection and exclusion criteria for Basic rules"; see the
``NOTICE`` beside it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from opentide.core.io import load_toml
from opentide.package.paths import bundled_data_root


def catalogue_path() -> Path:
    """The bundled copy of the criteria catalogue."""
    return bundled_data_root() / "bitdefender" / "criteria.toml"


@dataclass(frozen=True)
class Field:
    """One detection field of a target."""

    target: str
    #: The sensor that evaluates it: ``edr``, ``xdr`` or ``both``.
    availability: str
    relations: tuple[str, ...]
    #: ``string``, ``hash``, ``ip``, ``email``, ``port`` or ``enum``.
    kind: str
    #: Enum values and the sensor that evaluates each.
    values: dict[str, str] = field(default_factory=dict)
    #: Fields a rule using that enum value may not also have.
    value_incompatible: dict[str, tuple[str, ...]] = field(default_factory=dict)
    #: One of these must also be a criterion of the rule.
    requires_any: tuple[str, ...] = ()
    #: The same, in a detection rule, where ``detection`` is the block's ``alert``.
    detection_requires_any: tuple[str, ...] = ()
    #: Fields that may not be criteria of the same rule.
    incompatible: tuple[str, ...] = ()
    #: The XDR resource the field is about (one per connection rule).
    resource: str | None = None
    minimum: int | None = None
    maximum: int | None = None


@dataclass(frozen=True)
class Catalogue:
    #: Every detection field, by name.
    fields: dict[str, Field]
    #: Targets a detection rule may use.
    detection_targets: frozenset[str]
    #: Targets whose field list the spec states: an unknown field is an error there.
    closed_targets: frozenset[str]
    #: Full registry hive names and the short names GravityZone matches.
    registry_hives: dict[str, str]
    #: Targets with one XDR resource per rule (``one_resource``).
    one_resource_targets: frozenset[str]
    #: ``alert_or_operation`` rules: ``(target or None, field or None, scope, require)``.
    alert_or_operation: tuple[tuple[str | None, str | None, str, bool], ...]

    def target_fields(self, target: str) -> frozenset[str]:
        return frozenset(name for name, item in self.fields.items() if item.target == target)


def _field(raw: dict[str, Any]) -> Field:
    values = raw.get("values") or []
    return Field(
        target=str(raw["target"]),
        availability=str(raw["availability"]),
        relations=tuple(raw["relations"]),
        kind=str(raw["kind"]),
        values={str(v["name"]): str(v.get("availability", raw["availability"])) for v in values},
        value_incompatible={
            str(v["name"]): tuple(v["incompatible"]) for v in values if v.get("incompatible")
        },
        requires_any=tuple(raw.get("requires_any") or ()),
        detection_requires_any=tuple(raw.get("detection_requires_any") or ()),
        incompatible=tuple(raw.get("incompatible") or ()),
        resource=raw.get("resource"),
        minimum=raw.get("minimum"),
        maximum=raw.get("maximum"),
    )


def parse_catalogue(raw: dict[str, Any]) -> Catalogue:
    """The catalogue a ``criteria.toml`` document holds."""
    rules = raw.get("rules") or []
    one_resource: set[str] = set()
    for rule in rules:
        if rule.get("kind") == "one_resource":
            one_resource.update(rule.get("targets") or ())
    return Catalogue(
        fields={
            str(item["name"]): _field(item)
            for item in raw.get("fields") or []
            if item.get("detection")
        },
        detection_targets=frozenset(
            str(t["name"]) for t in raw.get("targets") or [] if t.get("detection")
        ),
        closed_targets=frozenset(
            str(t["name"]) for t in raw.get("targets") or [] if t.get("closed")
        ),
        registry_hives={str(k): str(v) for k, v in (raw.get("registry_hives") or {}).items()},
        one_resource_targets=frozenset(one_resource),
        alert_or_operation=tuple(
            (rule.get("target"), rule.get("field"), str(rule["scope"]), bool(rule["require"]))
            for rule in rules
            if rule.get("kind") == "alert_or_operation"
        ),
    )


@cache
def catalogue() -> Catalogue:
    """The bundled criteria catalogue, read once."""
    return parse_catalogue(load_toml(catalogue_path()))
