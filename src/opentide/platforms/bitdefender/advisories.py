"""Bitdefender advisories (bitdefender-1.0, Advisories): warnings that never reject a rule.

GravityZone accepts each of these, but the rule then does not do what its
author most likely meant. ``opentide validate`` reports them as warnings and
``opentide lint`` with its ``queries`` check, the way the engine's Sysdig
advisory is reported.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

REGISTRY_FULL_HIVE = "bitdefender_registry_full_hive"
CONTAINS_NO_WILDCARD = "bitdefender_contains_no_wildcard"
SEVERITY_COLLAPSED = "bitdefender_severity_collapsed"

ADVISORY_CODES = frozenset({REGISTRY_FULL_HIVE, CONTAINS_NO_WILDCARD, SEVERITY_COLLAPSED})

#: What GravityZone sends for an ``alert_severity`` it has no level for.
_COLLAPSED = {"critical": "High", "informational": "Low"}

_BLOCK = ("configurations", "bitdefender")


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
            path = (*_BLOCK, "detection", "criteria", str(index), relation)
            values = [v for v in _values(criterion, relation) if isinstance(v, str)]
            if field == "Registry.Key" and any(v.upper().startswith("HKEY_") for v in values):
                found.append(
                    Advisory(
                        REGISTRY_FULL_HIVE,
                        path,
                        "Registry.Key starts with a full hive name, which GravityZone accepts "
                        "and never matches; write HKLM, HKCU, HKU, HKCR, HKCC or HKLU",
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
    response = rule.get("response")
    severity = response.get("alert_severity") if isinstance(response, Mapping) else None
    collapsed = _COLLAPSED.get(str(severity).strip().lower()) if severity else None
    if collapsed is not None and block.get("severity") is None:
        found.append(
            Advisory(
                SEVERITY_COLLAPSED,
                ("response", "alert_severity"),
                f"GravityZone has three severities: alert_severity {severity} is sent as "
                f"{collapsed}; set configurations.bitdefender.severity to choose",
            )
        )
    return found
