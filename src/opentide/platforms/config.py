"""Per-platform system configuration loading for ``Platform.config``."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from opentide.core.index_manager import IndexManager
from opentide.models.system_config import ConfigurationModels, SystemConfig


def systems_raw_index() -> dict[str, dict[str, Any]]:
    return dict(IndexManager.load()["configurations"]["systems"])


#: Every detection system has a typed tenant model. Splunk and Carbon Black get
#: bespoke loaders below for their legacy key handling; the rest are built
#: generically. Before this mapping existed the generic branch handed callers
#: raw dicts, so ``tenant.name`` and ``tenant.setup.*`` raised ``AttributeError``
#: in both importers and in ``tenants_resolver`` (#242).
_SYSTEM_MODELS: dict[str, Any] = {
    "sentinel": ConfigurationModels.Systems.Sentinel,
    "splunk": ConfigurationModels.Systems.Splunk,
    "carbon_black_cloud": ConfigurationModels.Systems.CarbonBlackCloud,
    "sentinel_one": ConfigurationModels.Systems.SentinelOne,
    "defender_for_endpoint": ConfigurationModels.Systems.DefenderForEndpoint,
    "crowdstrike": ConfigurationModels.Systems.Crowdstrike,
    "harfanglab": ConfigurationModels.Systems.HarfangLab,
}

#: ``SystemConfig.Tenant.Setup`` declares these without defaults, but every
#: bundled TOML treats them as optional.
_SETUP_DEFAULTS: dict[str, Any] = {"proxy": False, "ssl": True}


def _required_fields(cls: Any) -> list[str]:
    return [
        item.name
        for item in dataclasses.fields(cls)
        if item.default is dataclasses.MISSING and item.default_factory is dataclasses.MISSING
    ]


def _build_section(cls: Any, payload: dict[str, Any], *, where: str) -> Any:
    """Instantiate a tenant dataclass, naming what the TOML is missing.

    A bare ``cls(**payload)`` raises ``TypeError: __init__() missing 1 required
    positional argument: 'workspace_id'``, which is what #242 surfaced to the
    user. Report the system, the tenant, and every missing key at once.
    """
    missing = [name for name in _required_fields(cls) if name not in payload]
    if missing:
        raise ValueError(f"{where} is missing required key(s): {', '.join(sorted(missing))}")
    known = {item.name for item in dataclasses.fields(cls)}
    return cls(**{key: value for key, value in payload.items() if key in known})


def _load_tenants(system: str, tenants_config: Any) -> list[Any]:
    """Typed tenants for any system without a bespoke loader."""
    from opentide.core.debug import DebugHelpers

    model = _SYSTEM_MODELS.get(system)
    if not tenants_config or model is None or not isinstance(tenants_config, list):
        return []
    tenant_cls = model.Tenant
    tenants: list[Any] = []
    for raw_tenant in tenants_config:
        if not isinstance(raw_tenant, dict):
            continue
        data = dict(raw_tenant)
        name = str(data.get("name") or "<unnamed>")
        where = f"{system} tenant {name!r}"
        if "name" not in data:
            raise ValueError(f"{where} is missing required key(s): name")
        setup_raw = dict(_SETUP_DEFAULTS)
        setup_raw.update(DebugHelpers.fetch_config_envvar(dict(data.get("setup") or {})))
        kwargs: dict[str, Any] = {
            "name": data["name"],
            "description": data.get("description", ""),
            "deployment": data.get("deployment", "ALWAYS"),
            "setup": _build_section(tenant_cls.Setup, setup_raw, where=f"{where} setup"),
        }
        parameters_cls = getattr(tenant_cls, "Parameters", None)
        parameters_raw = data.get("parameters")
        if (
            parameters_cls is not None
            and dataclasses.fields(parameters_cls)
            and isinstance(parameters_raw, dict)
        ):
            kwargs["parameters"] = _build_section(
                parameters_cls, parameters_raw, where=f"{where} parameters"
            )
        tenants.append(tenant_cls(**kwargs))
    return tenants


def _load_modifiers(
    modifiers_config: list[dict[str, Any]] | dict[str, Any] | None,
) -> list[SystemConfig.Modifiers]:
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


def _load_splunk_tenants(
    tenants_config: list[dict[str, Any]] | None,
) -> list[ConfigurationModels.Systems.Splunk.Tenant]:
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
    typed = ConfigurationModels.Systems.Splunk(
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


def _identity_platform(system: str, payload: dict[str, Any]) -> SystemConfig.Platform:
    """Tenant TOML ``[platform]`` identity — not a detection-rule platform config."""
    flags_raw = payload.get("flags") or []
    flags = [str(flag) for flag in flags_raw] if isinstance(flags_raw, list) else []
    return SystemConfig.Platform(
        enabled=bool(payload.get("enabled", False)),
        identifier=str(payload.get("identifier") or system),
        name=str(payload.get("name") or system),
        subschema=str(payload.get("subschema", "")),
        description=str(payload.get("description", "")),
        flags=flags,
    )


def build_system_config(system: str, raw: dict[str, Any] | None = None) -> Any:
    """Build typed platform configuration for a detection system."""
    raw = dict(systems_raw_index()[system]) if raw is None else dict(raw)
    if system == "splunk":
        return _build_splunk_config(raw)
    if system == "carbon_black_cloud":
        return _build_cbc_config(raw)
    raw_config = dict(raw)
    platform_payload = dict(raw_config.get("platform", {}))
    platform = _identity_platform(system, platform_payload) if platform_payload else None
    tenants = _load_tenants(system, raw_config.get("tenants"))
    return SimpleNamespace(
        raw=raw_config,
        platform=platform,
        modifiers=_load_modifiers(raw_config.get("modifiers")) or None,
        tenants=tenants or None,
    )
