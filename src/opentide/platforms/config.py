"""Per-platform system configuration loading for ``Platform.config``."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

from opentide.core.environment import ENV_REFERENCE, env_reference
from opentide.core.index_manager import IndexManager
from opentide.models.configuration.base import SSL_FALSE_WORDS, SSL_TRUE_WORDS
from opentide.models.configuration.platforms import PlatformConfigurationBase
from opentide.models.system_config import ConfigurationModels, SystemConfig


def systems_raw_index() -> dict[str, dict[str, Any]]:
    return dict(IndexManager.load()["configurations"]["systems"])


#: Every detection system has a typed tenant model. Splunk and Carbon Black get
#: bespoke tenant loaders below; the rest are built
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
    "elastic": ConfigurationModels.Systems.Elastic,
    "sysdig": ConfigurationModels.Systems.Sysdig,
    "bitdefender": ConfigurationModels.Systems.Bitdefender,
    "graylog": ConfigurationModels.Systems.Graylog,
    "google_secops": ConfigurationModels.Systems.GoogleSecops,
}

#: ``SystemConfig.Tenant.Setup`` declares these without defaults, but every
#: bundled TOML treats them as optional.
_SETUP_DEFAULTS: dict[str, Any] = {"ssl": True}

#: What replaces each value of the tenant ``deployment`` key, removed in 0.17.0.
_DEPLOYMENT_KEY_REPLACEMENT = {
    "STAGING": 'strategies = ["PREVIEW"]',
    "PRODUCTION": 'strategies = ["RELEASE"]',
    "ALWAYS": "no key at all (a tenant accepts every strategy by default)",
    "FULL": "no key at all (a tenant accepts every strategy by default)",
    "MANUAL": "manual = true",
    "DEBUG": 'strategies = ["PREVIEW"]',
}


def _tenant_targeting(data: dict[str, Any], *, where: str) -> dict[str, Any]:
    """Read a tenant's ``strategies`` and ``manual``; refuse the removed ``deployment`` key."""
    from opentide.models.deployment_enums import parse_strategies

    if "deployment" in data:
        value = str(data["deployment"]).strip().upper()
        replacement = _DEPLOYMENT_KEY_REPLACEMENT.get(
            value, 'strategies = ["PREVIEW"] or strategies = ["RELEASE"]'
        )
        raise ValueError(
            f"{where}: the tenant key 'deployment' was removed in 0.17.0. A tenant now lists "
            f"the status strategies it accepts. Replace deployment = {data['deployment']!r} "
            f"with {replacement}."
        )
    targeting: dict[str, Any] = {}
    if "strategies" in data:
        raw = data["strategies"]
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list) or not raw:
            raise ValueError(
                f"{where}: strategies must list PREVIEW, RELEASE, or both; "
                "omit it to accept every strategy"
            )
        targeting["strategies"] = parse_strategies(raw, source=f"{where} strategies:")
    if "manual" in data:
        if not isinstance(data["manual"], bool):
            raise ValueError(f"{where}: manual must be true or false")
        targeting["manual"] = data["manual"]
    return targeting


#: The same words the `platforms/<id>.toml` models and schemas accept.
_SSL_WORDS = {
    **dict.fromkeys(SSL_TRUE_WORDS, True),
    **dict.fromkeys(SSL_FALSE_WORDS, False),
}


def _tenant_ssl(value: Any, *, where: str) -> bool | str:
    """Read a tenant's ``ssl`` as a boolean.

    ``ssl = "$SPLUNK_SSL"`` resolves to the variable's text, and the string
    ``"false"`` is truthy: left as is it would verify the certificate the
    tenant asked not to. A placeholder whose variable is unset stays
    ``$NAME``, as for every other setup key; ``connect_splunk`` refuses it.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.startswith("$"):
            return value
        parsed = _SSL_WORDS.get(value.strip().lower())
        if parsed is not None:
            return parsed
    raise ValueError(f"{where} setup: ssl must be true or false, got {value!r}")


# platform::elastic::1.0: a tenant api_key MUST be `$VAR` or `${VAR}`.
_ENV_REFERENCE = ENV_REFERENCE


def setup_variables(value: Any) -> list[str]:
    """The environment variables a tenant's ``setup`` table names, in order, each once.

    A value is a reference when it is ``$NAME`` or ``${NAME}`` as a whole, and
    only a top-level value is one, as :meth:`DebugHelpers.fetch_config_envvar`
    resolves it (:func:`opentide.core.environment.env_reference`). Values are
    never returned, a ``$``-prefixed literal included.
    """
    names: list[str] = []
    if not isinstance(value, Mapping):
        return names
    for item in value.values():
        name = env_reference(item)
        if name is not None and name not in names:
            names.append(name)
    return names


_PROXY_RETIRED = (
    "The proxy key is retired. Pass the URL with `opentide --proxy http://[user:pass@]host:port`."
)


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


def _check_sysdig_setup(setup: dict[str, Any], *, where: str) -> None:
    """sysdig-1.0 tenant setup: `url` and `api_token`, the token as `$VAR`."""
    missing = [key for key in ("url", "api_token") if not setup.get(key)]
    if missing:
        raise ValueError(f"{where} setup is missing required key(s): {', '.join(missing)}")
    token = setup["api_token"]
    reference = _ENV_REFERENCE.fullmatch(token) if isinstance(token, str) else None
    if reference is None:
        raise ValueError(
            f"{where} setup: api_token must be an environment variable reference "
            "($VAR or ${VAR}, e.g. $SYSDIG_SECURE_API_TOKEN)"
        )
    setup["api_token"] = f"${reference.group(1) or reference.group(2)}"


#: ``[tenants.setup]`` keys of a Bitdefender tenant (bitdefender-1.0, Tenant setup).
_BITDEFENDER_SETUP_KEYS = frozenset(
    {
        "ssl",
        "url",
        "api_key",
        "key_type",
        "company_id",
        "automatic_actions",
        "targets",
        "endpoint_tags",
        "companies",
        "tags",
    }
)
_GRAVITYZONE_ID = re.compile(r"[0-9a-f]{24}")


def _check_gravityzone_id(value: Any, *, where: str, key: str) -> None:
    if not isinstance(value, str) or not _GRAVITYZONE_ID.fullmatch(value):
        raise ValueError(f"{where} setup: {key} must be a GravityZone id, 24 lower-case hex digits")


def _check_bitdefender_setup(setup: dict[str, Any], *, where: str) -> None:
    """bitdefender-1.0 tenant setup: known keys, `api_key` as `$VAR`, ids as 24 hex."""
    unknown = sorted(set(setup) - _BITDEFENDER_SETUP_KEYS)
    if unknown:
        raise ValueError(f"{where} setup has unknown key(s): {', '.join(unknown)}")
    missing = [key for key in ("url", "api_key") if not setup.get(key)]
    if missing:
        raise ValueError(f"{where} setup is missing required key(s): {', '.join(missing)}")
    key = setup["api_key"]
    reference = _ENV_REFERENCE.fullmatch(key) if isinstance(key, str) else None
    if reference is None:
        raise ValueError(
            f"{where} setup: api_key must be an environment variable reference "
            "($VAR or ${VAR}, e.g. $GRAVITYZONE_API_KEY)"
        )
    setup["api_key"] = f"${reference.group(1) or reference.group(2)}"
    if setup.get("key_type", "personal") not in ("personal", "service"):
        raise ValueError(f"{where} setup: key_type must be personal or service")
    if setup.get("company_id") is not None:
        _check_gravityzone_id(setup["company_id"], where=where, key="company_id")
    endpoint_tags = setup.get("endpoint_tags") or {}
    if not isinstance(endpoint_tags, dict):
        raise ValueError(f"{where} setup: endpoint_tags must be a table of aliases")
    for alias, entry in endpoint_tags.items():
        if not isinstance(entry, dict) or set(entry) != {"tag_id", "company_id"}:
            raise ValueError(f"{where} setup: endpoint_tags.{alias} must be {{tag_id, company_id}}")
        for name in ("tag_id", "company_id"):
            _check_gravityzone_id(entry[name], where=where, key=f"endpoint_tags.{alias}.{name}")
    companies = setup.get("companies") or {}
    if not isinstance(companies, dict):
        raise ValueError(f"{where} setup: companies must be a table of aliases")
    for alias, company in companies.items():
        _check_gravityzone_id(company, where=where, key=f"companies.{alias}")
    targets = setup.get("targets")
    if targets is not None:
        from opentide.platforms.bitdefender.catalog import targets_codes

        if (
            not isinstance(targets, dict)
            or set(targets) - {"endpoint_tags", "companies"}
            or not targets
            or targets_codes(targets)
        ):
            raise ValueError(
                f"{where} setup: targets must be {{endpoint_tags = [...]}} or {{companies = [...]}}"
            )


#: ``[tenants.setup]`` keys of a Graylog tenant (graylog-1.0, Tenant setup).
_GRAYLOG_SETUP_KEYS = frozenset(
    {
        "ssl",
        "url",
        "token",
        "allow_leading_wildcard",
        "streams",
        "stream_ids",
        "notification_ids",
        "tags",
    }
)


def _check_graylog_names(value: Any, *, where: str, key: str) -> None:
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not all(
        isinstance(item, str) and item.strip() for item in items
    ):
        raise ValueError(f"{where} setup: {key} must be a string or a list of non-blank strings")


def _check_graylog_setup(setup: dict[str, Any], *, where: str) -> None:
    """graylog-1.0 tenant setup: known keys, `token` as `$VAR`, ids as 24 hex."""
    unknown = sorted(set(setup) - _GRAYLOG_SETUP_KEYS)
    if unknown:
        raise ValueError(f"{where} setup has unknown key(s): {', '.join(unknown)}")
    missing = [key for key in ("url", "token") if not setup.get(key)]
    if missing:
        raise ValueError(f"{where} setup is missing required key(s): {', '.join(missing)}")
    token = setup["token"]
    reference = _ENV_REFERENCE.fullmatch(token) if isinstance(token, str) else None
    if reference is None:
        raise ValueError(
            f"{where} setup: token must be an environment variable reference "
            "($VAR or ${VAR}, e.g. $GRAYLOG_TOKEN)"
        )
    setup["token"] = f"${reference.group(1) or reference.group(2)}"
    if not isinstance(setup.get("allow_leading_wildcard", False), bool):
        raise ValueError(f"{where} setup: allow_leading_wildcard must be true or false")
    for key in ("streams", "tags"):
        if setup.get(key) is not None:
            _check_graylog_names(setup[key], where=where, key=key)
    for table in ("stream_ids", "notification_ids"):
        entries = setup.get(table) or {}
        if not isinstance(entries, dict):
            raise ValueError(f"{where} setup: {table} must be a table of aliases")
        for alias, value in entries.items():
            if not isinstance(value, str) or not _GRAVITYZONE_ID.fullmatch(value):
                raise ValueError(
                    f"{where} setup: {table}.{alias} must be a Graylog id, 24 lower-case hex digits"
                )


#: ``[tenants.setup]`` keys of a Google SecOps tenant (google-secops-1.0, Tenant setup).
_GOOGLE_SECOPS_SETUP_KEYS = frozenset(
    {
        "ssl",
        "project",
        "location",
        "instance",
        "endpoint",
        "credentials",
        "data_access_scope",
        "deletion",
    }
)


def _check_google_secops_setup(setup: dict[str, Any], *, where: str) -> None:
    """google-secops-1.0 tenant setup: known keys, `credentials` as `$VAR`, a known deletion."""
    unknown = sorted(set(setup) - _GOOGLE_SECOPS_SETUP_KEYS)
    if unknown:
        raise ValueError(f"{where} setup has unknown key(s): {', '.join(unknown)}")
    missing = [key for key in ("project", "location", "instance") if not setup.get(key)]
    if missing:
        raise ValueError(f"{where} setup is missing required key(s): {', '.join(missing)}")
    credentials = setup.get("credentials")
    if credentials is not None:
        reference = _ENV_REFERENCE.fullmatch(credentials) if isinstance(credentials, str) else None
        if reference is None:
            raise ValueError(
                f"{where} setup: credentials must be an environment variable reference "
                "($VAR or ${VAR}, e.g. $GOOGLE_SECOPS_CREDENTIALS) whose value is a "
                "service-account key or the path to one; leave it out to use Application "
                "Default Credentials"
            )
        setup["credentials"] = f"${reference.group(1) or reference.group(2)}"
    if setup.get("deletion", "archive") not in ("archive", "delete"):
        raise ValueError(f"{where} setup: deletion must be archive or delete")


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
        supplied_setup = dict(data.get("setup") or {})
        if "proxy" in supplied_setup:
            raise ValueError(f"{where}: {_PROXY_RETIRED}")
        if system == "elastic":
            raw_key = supplied_setup.get("api_key")
            if raw_key is not None:
                reference = _ENV_REFERENCE.fullmatch(raw_key) if isinstance(raw_key, str) else None
                if reference is None:
                    raise ValueError(
                        f"{where} setup: api_key must be an environment variable reference "
                        "($VAR or ${VAR}, e.g. $ELASTIC_API_KEY)"
                    )
                # The resolver reads `$NAME`; hand it the braced form that way.
                supplied_setup["api_key"] = f"${reference.group(1) or reference.group(2)}"
        if system == "sysdig":
            _check_sysdig_setup(supplied_setup, where=where)
        if system == "bitdefender":
            _check_bitdefender_setup(supplied_setup, where=where)
        if system == "graylog":
            _check_graylog_setup(supplied_setup, where=where)
        if system == "google_secops":
            _check_google_secops_setup(supplied_setup, where=where)
        setup_raw = dict(_SETUP_DEFAULTS)
        setup_raw.update(DebugHelpers.fetch_config_envvar(supplied_setup))
        setup_raw["ssl"] = _tenant_ssl(setup_raw["ssl"], where=where)
        kwargs: dict[str, Any] = {
            "name": data["name"],
            "description": data.get("description", ""),
            **_tenant_targeting(data, where=where),
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


def _reject_setup_proxy(setup_raw: dict[str, Any], *, where: str) -> None:
    if "proxy" in setup_raw:
        raise ValueError(f"{where}: {_PROXY_RETIRED}")


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
        _reject_setup_proxy(
            setup_raw, where=f"splunk tenant {tenant_data.get('name', '<unnamed>')!r}"
        )
        setup = ConfigurationModels.Systems.Splunk.Tenant.Setup(
            ssl=_tenant_ssl(
                setup_raw.get("ssl", True),
                where=f"splunk tenant {tenant_data.get('name', '<unnamed>')!r}",
            ),
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
                setup=setup,
                **_tenant_targeting(
                    tenant_data, where=f"splunk tenant {tenant_data.get('name', '<unnamed>')!r}"
                ),
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
        _reject_setup_proxy(
            setup_raw,
            where=f"carbon_black_cloud tenant {tenant_data.get('name', '<unnamed>')!r}",
        )
        setup = ConfigurationModels.Systems.CarbonBlackCloud.Tenant.Setup(
            ssl=_tenant_ssl(
                setup_raw.get("ssl", True),
                where=f"carbon_black_cloud tenant {tenant_data.get('name', '<unnamed>')!r}",
            ),
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
                setup=setup,
                **_tenant_targeting(
                    tenant_data,
                    where=f"carbon_black_cloud tenant {tenant_data.get('name', '<unnamed>')!r}",
                ),
            )
        )
    return tenants


def _identity_platform(system: str, payload: dict[str, Any]) -> SystemConfig.Platform:
    """The ``[platform]`` table of a platform file; *system* is the file name stem."""
    return SystemConfig.Platform(
        enabled=bool(payload.get("enabled", False)),
        identifier=system,
        name=str(payload.get("name") or system),
        description=str(payload.get("description", "")),
    )


def _build_splunk_config(raw: dict[str, Any]) -> Any:
    platform = _identity_platform("splunk", dict(raw.get("platform") or {}))
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
        Index=raw,
    )


def _build_cbc_config(raw: dict[str, Any]) -> Any:
    platform = _identity_platform("carbon_black_cloud", dict(raw.get("platform") or {}))
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
        Index=raw,
    )


def validate_platform_config(system: str, raw: dict[str, Any]) -> PlatformConfigurationBase | None:
    """Validate a merged `platforms/<system>.toml` against its model.

    Values are checked as written: a `$NAME` placeholder is valid for any
    setup key, so no secret is resolved or repeated here. A platform plugin
    (an `opentide.platforms` entry point) owns its file, so only the built-in
    platforms are validated; the call returns `None` for any other.
    """
    from opentide.models.configuration.loading import validate_configuration
    from opentide.models.configuration.platforms import PLATFORM_CONFIGURATION_MODELS

    model = PLATFORM_CONFIGURATION_MODELS.get(system)
    if model is None:
        return None
    return validate_configuration(model, raw, file_key=f"platforms/{system}.toml")


def build_system_config(system: str, raw: dict[str, Any] | None = None) -> Any:
    """Build typed platform configuration for a detection system.

    The tenant loaders run first and report a retired or missing key in the
    words they always have; the platform model then rejects whatever they
    do not read (an unknown key, a wrong type).
    """
    raw = dict(systems_raw_index()[system]) if raw is None else dict(raw)
    built = _build_system_config(system, raw)
    validate_platform_config(system, raw)
    return built


def _build_system_config(system: str, raw: dict[str, Any]) -> Any:
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
