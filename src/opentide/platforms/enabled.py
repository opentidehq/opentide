"""Enabled platform discovery from merged configuration."""

from __future__ import annotations
from opentide.core.files import resolve_configurations

SYSTEM_KEYS = (
    "sentinel",
    "defender_for_endpoint",
    "splunk",
    "sentinel_one",
    "crowdstrike",
    "harfanglab",
    "carbon_black_cloud",
)


def enabled_systems() -> list[str]:
    """Return platform identifiers marked enabled in merged system configuration."""
    systems = resolve_configurations().get("systems", {})
    enabled: list[str] = []
    for system in SYSTEM_KEYS:
        config = systems.get(system)
        if not config:
            continue
        tide_block = config.get("tide", {})
        platform_block = config.get("platform", {})
        if tide_block.get("enabled") is True or platform_block.get("enabled") is True:
            enabled.append(system)
    return enabled
