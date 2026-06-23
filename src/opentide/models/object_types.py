"""Canonical OpenTide core object type keys and schema identifiers."""

from __future__ import annotations

THREAT = "threat"
OBJECTIVE = "objective"
RULE = "rule"
SIGNAL = "signal"

CORE_OBJECT_TYPES = (THREAT, OBJECTIVE, RULE)

SCHEMA_IDENTIFIERS: dict[str, str] = {
    THREAT: "threat::1.0",
    OBJECTIVE: "objective::1.0",
    RULE: "rule::1.0",
}
