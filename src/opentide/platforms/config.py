"""Per-platform system configuration loading for ``Platform.config``."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from opentide.core.index_manager import IndexManager
from opentide.models.platform import parse_platform_config
from opentide.models.system_config import ConfigurationModels, SystemConfig


def systems_raw_index() -> dict[str, dict[str, Any]]:
    return dict(IndexManager.load()["configurations"]["systems"])


def _load_modifiers(modifiers_config: list[dict[str, Any]] | dict[str, Any] | None) -> list[SystemConfig.Modifiers]:
    if not modifiers_config:
        return []
    if isinstance(modifiers_config, dict):
        return []
    modifiers: list[SystemConfig.Modifiers] = []
    for modifier in modifiers_config:
        conditions = SystemConfig.Modifiers.Conditions(**modifier["conditions"])
        modifiers.append(
            SystemConfig.Modifiers(
                conditions=conditions,
                modifications=modifier["modifications"],
                name=modifier.get("name"),
                description=modifier.get("description"),
            )
        )
    return modifiers


def _load_splunk_tenants(tenants_config: list[dict[str, Any]] | None) -> list[ConfigurationModels.Systems.Splunk.Tenant]:
    from opentide.core.debug import DebugHelpers

    if not tenants_config:
        return []
    tenants: list[ConfigurationModels.Systems.Splunk.Tenant] = []
    for tenant in tenants_config:
        tenant_data = dict(tenant)
        setup_raw = DebugHelpers.fetch_config_envvar(dict(tenant_data.pop("setup", {})))
        setup = ConfigurationModels.Systems.Splunk.Tenant.Setup(
            proxy=setup_raw.get("proxy", False),
            ssl=setup_raw.get("ssl", True),
            url=setup_raw["url"],
            port=setup_raw["port"],
            app=setup_raw["app"],
            correlation_searches=setup_raw.get("correlation_searches", True),
            allow_skew=setup_raw.get("allow_skew"),
            schedule_offset=int(setup_raw.get("schedule_offset", 0)),
            frequency_scheduling=setup_raw.get("frequency_scheduling", "random"),
            actions_enabled=setup_raw.get("actions_enabled"),
            default_actions=setup_raw.get("default_actions"),
            enterprise_security=setup_raw.get("enterprise_security", False),
            token=setup_raw.get("token", ""),
        )
        tenants.append(
            ConfigurationModels.Systems.Splunk.Tenant(
                name=tenant_data["name"],
                description=tenant_data.get("description", ""),
                deployment=tenant_data.get("deployment", "ALWAYS"),
                setup=setup,
            )
        )
    return tenants


def _load_cbc_tenants(
    tenants_config: list[dict[str, Any]] | None,
) -> list[ConfigurationModels.Systems.CarbonBlackCloud.Tenant]:
    from opentide.core.debug import DebugHelpers

    if not tenants_config:
        return []
    tenants: list[ConfigurationModels.Systems.CarbonBlackCloud.Tenant] = []
    for tenant in tenants_config:
        tenant_data = dict(tenant)
        setup_raw = DebugHelpers.fetch_config_envvar(dict(tenant_data.pop("setup", {})))
        setup = ConfigurationModels.Systems.CarbonBlackCloud.Tenant.Setup(
            proxy=setup_raw.get("proxy", False),
            ssl=setup_raw.get("ssl", True),
            url=setup_raw["url"],
            org_key=setup_raw["org_key"],
            token=setup_raw["token"],
            watchlist=setup_raw.get("watchlist"),
            organizations=setup_raw.get("organizations"),
        )
        tenants.append(
            ConfigurationModels.Systems.CarbonBlackCloud.Tenant(
                name=tenant_data["name"],
                description=tenant_data.get("description", ""),
                deployment=tenant_data.get("deployment", "ALWAYS"),
                setup=setup,
            )
        )
    return tenants


def _build_splunk_config(raw: dict[str, Any]) -> Any:
    @dataclass(frozen=True)
    class SplunkLegacyAttrs:
        Index: dict[str, Any]
        tide: dict[str, Any]
        setup: dict[str, Any]
        secrets: dict[str, Any]
        defaults: dict[str, Any]
        modifiers: dict[str, Any]

    legacy = SplunkLegacyAttrs(
        Index=raw,
        tide=dict(raw.get("tide", {})),
        setup=dict(raw.get("setup", {})),
        secrets=dict(raw.get("secrets", {})),
        defaults=dict(raw.get("defaults", {})),
        modifiers=dict(raw.get("modifiers", {})),
    )

    if "platform" not in raw:
        return SimpleNamespace(
            Index=legacy.Index,
            tide=legacy.tide,
            setup=legacy.setup,
            secrets=legacy.secrets,
            defaults=legacy.defaults,
            modifiers=legacy.modifiers,
            tenants=None,
        )

    platform_payload = dict(raw["platform"])
    platform = SystemConfig.Platform(
        enabled=platform_payload.get("enabled", False),
        identifier=platform_payload.get("identifier", "splunk"),
        name=platform_payload.get("name", "Splunk"),
        subschema=platform_payload.get("subschema", "Splunk Sub Schema"),
        description=platform_payload.get("description", ""),
        flags=list(platform_payload.get("flags", [])),
    )
    tenants = _load_splunk_tenants(raw.get("tenants"))
    modifiers = _load_modifiers(raw.get("modifiers"))
    typed = ConfigurationModels.Systems.Splunk(platform=platform, tenants=tenants, modifiers=modifiers)
    return SimpleNamespace(
        raw=raw,
        platform=platform,
        tenants=tenants or None,
        modifiers=modifiers or None,
        typed=typed,
        tide=legacy.tide,
        setup=legacy.setup,
        secrets=legacy.secrets,
        defaults=legacy.defaults,
        Index=legacy.Index,
    )


def _build_cbc_config(raw: dict[str, Any]) -> Any:
    @dataclass(frozen=True)
    class CarbonBlackLegacyAttrs:
        Index: dict[str, Any]
        tide: dict[str, Any]
        setup: dict[str, Any]
        secrets: dict[str, Any]
        validation: dict[str, Any]

    legacy = CarbonBlackLegacyAttrs(
        Index=raw,
        tide=dict(raw.get("tide", {})),
        setup=dict(raw.get("setup", {})),
        secrets=dict(raw.get("secrets", {})),
        validation=dict(raw.get("validation", {})),
    )

    if "platform" not in raw:
        return SimpleNamespace(
            Index=legacy.Index,
            tide=legacy.tide,
            setup=legacy.setup,
            secrets=legacy.secrets,
            validation=legacy.validation,
            tenants=None,
        )

    platform_payload = dict(raw["platform"])
    platform = SystemConfig.Platform(
        enabled=platform_payload.get("enabled", False),
        identifier=platform_payload.get("identifier", "carbon_black_cloud"),
        name=platform_payload.get("name", "Carbon Black Cloud"),
        subschema=platform_payload.get("subschema", "CBC EDR Sub Schema"),
        description=platform_payload.get("description", ""),
        flags=list(platform_payload.get("flags", [])),
    )
    tenants = _load_cbc_tenants(raw.get("tenants"))
    modifiers = _load_modifiers(raw.get("modifiers"))
    typed = ConfigurationModels.Systems.CarbonBlackCloud(
        platform=platform, tenants=tenants, modifiers=modifiers
    )
    return SimpleNamespace(
        raw=raw,
        platform=platform,
        tenants=tenants or None,
        modifiers=modifiers or None,
        typed=typed,
        tide=legacy.tide,
        setup=legacy.setup,
        secrets=legacy.secrets,
        validation=legacy.validation,
        Index=legacy.Index,
    )


def build_system_config(system: str, raw: dict[str, Any] | None = None) -> Any:
    """Build typed platform configuration for a detection system."""
    index = systems_raw_index()
    raw = dict(raw if raw is not None else index[system])
    if system == "splunk":
        return _build_splunk_config(raw)
    if system == "carbon_black_cloud":
        return _build_cbc_config(raw)
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
