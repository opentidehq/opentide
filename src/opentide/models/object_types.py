"""Canonical OpenTide core object type keys (folder routing)."""

from __future__ import annotations

THREAT = "threat"
OBJECTIVE = "objective"
RULE = "rule"
SIGNAL = "signal"

CORE_OBJECT_TYPES = (THREAT, OBJECTIVE, RULE)


def latest_identifier(family: str) -> str:
    """Latest registered schema identifier for a core object family."""
    from opentide.models.schema_registry import latest_identifier as registry_latest

    return registry_latest(family)
