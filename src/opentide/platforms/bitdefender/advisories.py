"""Bitdefender advisories (bitdefender-1.0, Advisories): warnings that never reject a rule.

GravityZone accepts each of these, but the rule then does not do what its
author most likely meant. ``opentide validate`` reports them as warnings and
``opentide lint`` with its ``queries`` check, the way the engine's Sysdig
advisory is reported.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from opentide.platforms.bitdefender.criteria import catalogue

REGISTRY_FULL_HIVE = "bitdefender_registry_full_hive"
CONTAINS_NO_WILDCARD = "bitdefender_contains_no_wildcard"
SEVERITY_COLLAPSED = "bitdefender_severity_collapsed"

#: An unknown field on a target outside the spec's table: the constraint code, as a warning.
UNKNOWN_FIELD = "bitdefender_criterion_field"

ADVISORY_CODES = frozenset({REGISTRY_FULL_HIVE, CONTAINS_NO_WILDCARD, SEVERITY_COLLAPSED})

#: What GravityZone sends for an ``alert_severity`` it has no level for.
_COLLAPSED = {"critical": "High", "informational": "Low"}

_BLOCK = ("configurations", "bitdefender")

#: ``HKEY_USERS\\<SID>``: a user's hive, which GravityZone names ``HKU``.
_USER_SID = re.compile(r"S-\d+-\d+(?:-\d+)*(?:\\|$)", re.IGNORECASE)


def short_hive(key: str) -> str | None:
    """The short hive name GravityZone matches for *key*'s full hive name, or ``None``.

    Compared case-insensitively. ``HKEY_USERS\\<SID>…`` is ``HKU``; any other
    ``HKEY_USERS\\…`` key is ``HKLU`` (bitdefender-1.0, Advisories).
    """
    hive, _, rest = key.partition("\\")
    upper = hive.upper()
    if upper == "HKEY_USERS":
        return "HKU" if _USER_SID.match(rest) else "HKLU"
    return catalogue().registry_hives.get(upper)


@dataclass(frozen=True)
class Advisory:
    code: str
    field_path: tuple[str, ...]
    message: str


def _values(criterion: Mapping[str, Any], relation: str) -> list[Any]:
    value = criterion.get(relation)
    return list(value) if relation == "any" and isinstance(value, list) else [value]


def _criteria_advisories(detection: Mapping[str, Any]) -> list[Advisory]:
    found: list[Advisory] = []
    criteria = detection.get("criteria")
    if not isinstance(criteria, list):
        return found
    for index, criterion in enumerate(criteria):
        if not isinstance(criterion, Mapping):
            continue
        field = criterion.get("field")
        for relation in ("is", "contains", "any"):
            if relation not in criterion:
                continue
            path = (*_BLOCK, "detection", "criteria", str(index))
            values = [v for v in _values(criterion, relation) if isinstance(v, str)]
            hints = [hint for v in values if field == "Registry.Key" and (hint := short_hive(v))]
            if hints:
                found.append(
                    Advisory(
                        REGISTRY_FULL_HIVE,
                        path,
                        "Registry.Key starts with a full hive name, which GravityZone accepts "
                        f"and never matches; write {hints[0]}",
                    )
                )
            if relation == "contains" and values and not any(c in values[0] for c in "*?"):
                found.append(
                    Advisory(
                        CONTAINS_NO_WILDCARD,
                        path,
                        f"contains {values[0]!r} has no * or ? wildcard, so GravityZone matches "
                        f"it as written; write '*{values[0]}*' for a substring",
                    )
                )
    return found


def bitdefender_advisories(rule: Mapping[str, Any]) -> list[Advisory]:
    """Every advisory the rule's ``bitdefender`` block, as authored, earns."""
    configurations = rule.get("configurations")
    block = configurations.get("bitdefender") if isinstance(configurations, Mapping) else None
    if not isinstance(block, Mapping):
        return []
    found: list[Advisory] = []
    detection = block.get("detection")
    if isinstance(detection, Mapping):
        found.extend(_criteria_advisories(detection))
        from opentide.platforms.bitdefender.catalog import unknown_field_paths

        # On a target whose field list the spec does not state, an unknown field
        # is a warning until the catalogue covers it (bitdefender-1.0).
        found.extend(
            Advisory(
                UNKNOWN_FIELD,
                (*_BLOCK, *path),
                f"the criteria catalogue lists no such field for target {detection['target']!r}; "
                "GravityZone may refuse it",
            )
            for path in unknown_field_paths(detection)
        )
    response = rule.get("response")
    severity = response.get("alert_severity") if isinstance(response, Mapping) else None
    collapsed = _COLLAPSED.get(str(severity).strip().lower()) if severity else None
    if collapsed is not None and block.get("severity") is None:
        found.append(
            Advisory(
                SEVERITY_COLLAPSED,
                _BLOCK,
                f"GravityZone has three severities: alert_severity {severity} is sent as "
                f"{collapsed}; set configurations.bitdefender.severity to choose",
            )
        )
    return found
