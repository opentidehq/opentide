"""Per-platform system configuration loading for ``Platform.config``."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from opentide.core.index_manager import IndexManager
from opentide.models.platform import parse_platform_config


def systems_raw_index() -> dict[str, dict[str, Any]]:
    return dict(IndexManager.load()["configurations"]["systems"])


def build_system_config(system: str, raw: dict[str, Any] | None = None) -> Any:
    """Build typed platform configuration for a detection system."""
    index = systems_raw_index()
    raw = dict(raw if raw is not None else index[system])
    if system == "splunk":

        @dataclass(frozen=True)
        class SplunkSystemConfig:
            Index: dict[str, Any]
            tide: dict[str, Any]
            setup: dict[str, Any]
            secrets: dict[str, Any]
            defaults: dict[str, Any]
            modifiers: dict[str, Any]

        return SplunkSystemConfig(
            Index=raw,
            tide=dict(raw["tide"]),
            setup=dict(raw["setup"]),
            secrets=dict(raw["secrets"]),
            defaults=dict(raw["defaults"]),
            modifiers=dict(raw.get("modifiers", {})),
        )
    if system == "carbon_black_cloud":

        @dataclass(frozen=True)
        class CarbonBlackSystemConfig:
            Index: dict[str, Any]
            tide: dict[str, Any]
            setup: dict[str, Any]
            secrets: dict[str, Any]
            validation: dict[str, Any]

        return CarbonBlackSystemConfig(
            Index=raw,
            tide=dict(raw["tide"]),
            setup=dict(raw["setup"]),
            secrets=dict(raw["secrets"]),
            validation=dict(raw["validation"]),
        )
    platform_key = {
        "sentinel": "sentinel",
        "defender_for_endpoint": "defender_for_endpoint",
        "sentinel_one": "sentinel_one",
        "crowdstrike": "crowdstrike",
        "harfanglab": "harfanglab",
    }[system]
    raw_config = dict(raw)
    platform_payload = dict(raw_config.get("platform", {}))
    platform = parse_platform_config(platform_key, platform_payload) if platform_payload else None
    return SimpleNamespace(
        raw=raw_config,
        platform=platform,
        modifiers=raw_config.get("modifiers"),
        tenants=raw_config.get("tenants"),
    )
