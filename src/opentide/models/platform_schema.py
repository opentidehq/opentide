"""Platform configuration schema metadata for template and deployer generation."""

from __future__ import annotations

from typing import Any

from opentide.models.base import TideModel
from opentide.models.platform import (
    PLATFORM_CONFIG_MODELS,
    CarbonBlackConfig,
    CrowdstrikeConfig,
    DefenderConfig,
    HarfangLabConfig,
    SentinelConfig,
    SentinelOneConfig,
    SplunkConfig,
)

_COMMON_PLATFORM_EXTRAS: dict[str, Any] = {
    "required": ["status", "query"],
    "tide.template.force-required": ["schema"],
    "property_extras": {
        "platform_schema": {
            "title": "Schema identifier and version",
            "tide.template.force-required": True,
        },
        "status": {
            "title": "Status of the use-case",
            "tide.config.statuses": True,
        },
        "contributors": {
            "title": "Development Contributors",
        },
        "tenants": {
            "title": "Target Tenants",
        },
        "query": {
            "tide.template.multiline": True,
            "tide.template.spacer": True,
        },
    },
}

_PLATFORM_EXTRAS: dict[type[TideModel], dict[str, Any]] = {
    SplunkConfig: {
        "required": ["status", "query", "scheduling"],
        "tide.template.force-required": ["platform_schema"],
        "property_extras": {
            **_COMMON_PLATFORM_EXTRAS["property_extras"],
            "platform_schema": {
                "title": "Schema identifier and version",
                "default": "splunk::2.1",
                "pattern": r"^splunk::[1-9]\.[0-9]$",
            },
            "threshold": {"tide.mdr.parameter": "alert_threshold"},
            "throttling": {
                "properties": {
                    "fields": {"tide.mdr.parameter": "alert.suppress.fields"},
                    "duration": {"tide.mdr.parameter": "alert.suppress.period"},
                },
            },
            "scheduling": {
                "properties": {
                    "cron": {"tide.mdr.parameter": "cron_schedule"},
                    "lookback": {"tide.mdr.parameter": "dispatch.earliest_time"},
                },
            },
            "notable": {
                "properties": {
                    "event": {
                        "properties": {
                            "title": {"tide.mdr.parameter": "action.notable.param.rule_title"},
                            "description": {
                                "tide.mdr.parameter": "action.notable.param.rule_description",
                                "tide.template.multiline": True,
                            },
                        },
                    },
                    "drilldown": {
                        "properties": {
                            "name": {"tide.mdr.parameter": "action.notable.param.drilldown_name"},
                            "search": {
                                "tide.mdr.parameter": "action.notable.param.drilldown_search",
                            },
                        },
                    },
                    "security_domain": {
                        "tide.mdr.parameter": "action.notable.param.security_domain",
                    },
                },
            },
            "security_domain": {
                "tide.template.hide": True,
                "tide.meta.deprecation": "security_domain is now nested under the notable block",
                "tide.mdr.parameter": "action.notable.param.security_domain",
            },
            "risk": {
                "tide.mdr.parameter": "action.risk.param._risk",
                "properties": {
                    "message": {"tide.mdr.parameter": "action.risk.param._risk_message"},
                    "risk_objects": {
                        "items": {
                            "properties": {
                                "field": {"tide.mdr.parameter": "risk_object_field"},
                                "type": {"tide.mdr.parameter": "risk_object_type"},
                                "score": {"tide.mdr.parameter": "risk_score"},
                            },
                        },
                    },
                    "threat_objects": {
                        "items": {
                            "properties": {
                                "field": {"tide.mdr.parameter": "threat_object_field"},
                                "type": {"tide.mdr.parameter": "threat_object_type"},
                            },
                        },
                    },
                },
            },
            "advanced": {"tide.template.hide": True},
        },
    },
    SentinelConfig: {
        "required": ["status", "query", "scheduling", "alert", "grouping", "entities"],
        "tide.template.force-required": ["trigger", "operator", "threshold"],
        "property_extras": {
            **_COMMON_PLATFORM_EXTRAS["property_extras"],
            "platform_schema": {"default": "sentinel::2.4"},
            "tenants": {"tide.config.system.tenants": "sentinel"},
        },
    },
    DefenderConfig: {
        "required": ["status", "query", "alert", "impacted_entities", "scheduling"],
        "property_extras": {
            **_COMMON_PLATFORM_EXTRAS["property_extras"],
            "platform_schema": {"default": "defender_for_endpoint::2.3"},
            "tenants": {"tide.config.system.tenants": "defender_for_endpoint"},
        },
    },
    SentinelOneConfig: {
        "required": ["status", "condition"],
        "property_extras": {
            **_COMMON_PLATFORM_EXTRAS["property_extras"],
            "platform_schema": {"default": "sentinel_one::2.0"},
            "tenants": {"tide.config.system.tenants": "sentinel_one"},
        },
    },
    CrowdstrikeConfig: {
        "required": ["status", "query", "details", "schedule"],
        "property_extras": {
            **_COMMON_PLATFORM_EXTRAS["property_extras"],
            "platform_schema": {"default": "crowdstrike::2.0"},
            "tenants": {"tide.config.system.tenants": "crowdstrike"},
        },
    },
    HarfangLabConfig: {
        "required": ["status"],
        "property_extras": {
            **_COMMON_PLATFORM_EXTRAS["property_extras"],
            "platform_schema": {"default": "harfanglab::2.0"},
            "tenants": {"tide.config.system.tenants": "harfanglab"},
        },
    },
    CarbonBlackConfig: {
        "required": ["status"],
        "property_extras": {
            **_COMMON_PLATFORM_EXTRAS["property_extras"],
            "platform_schema": {"default": "carbon_black_cloud::2.0"},
            "tenants": {"tide.config.system.tenants": "carbon_black_cloud"},
        },
    },
}

_PLATFORM_KEY_BY_MODEL: dict[type[TideModel], str] = {
    model: key for key, model in PLATFORM_CONFIG_MODELS.items()
}


def platform_root_extras(model: type[TideModel]) -> dict[str, Any]:
    """Return root-level schema extras for a platform configuration model."""
    return dict(_PLATFORM_EXTRAS.get(model, _COMMON_PLATFORM_EXTRAS))


def platform_model_for_key(key: str) -> type[TideModel]:
    """Resolve a platform registry key to its configuration model."""
    return PLATFORM_CONFIG_MODELS[key]


def platform_model_for_subschema_name(subschema_name: str) -> type[TideModel] | None:
    """Resolve a legacy subschema file stem to a platform model."""
    mapping = {
        "Splunk Sub Schema": SplunkConfig,
        "Microsoft Sentinel": SentinelConfig,
        "Defender for Endpoint": DefenderConfig,
        "Sentinel One": SentinelOneConfig,
        "Crowdstrike": CrowdstrikeConfig,
        "HarfangLab": HarfangLabConfig,
        "CBC EDR Sub Schema": CarbonBlackConfig,
    }
    return mapping.get(subschema_name)
