"""Platforms whose queries can be checked against a tenant.

CrowdStrike and HarfangLab expose no query language, so their capability
entry is ``can_validate False``.
"""

from __future__ import annotations

QUERY_VALIDATION_PLATFORMS: frozenset[str] = frozenset(
    {
        "sentinel",
        "defender_for_endpoint",
        "splunk",
        "sentinel_one",
        "carbon_black_cloud",
        "elastic",
    }
)
