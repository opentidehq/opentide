"""Platform block schema metadata for editor schemas and templates."""

from __future__ import annotations

from typing import Any

from opentide.models.base import TideModel
from opentide.models.platform import (
    PLATFORM_CONFIG_MODELS,
    BitdefenderConfig,
    CarbonBlackConfig,
    CrowdstrikeConfig,
    DefenderConfig,
    ElasticConfig,
    ExabeamConfig,
    GoogleSecopsConfig,
    GraylogConfig,
    HarfangLabConfig,
    SentinelConfig,
    SentinelOneConfig,
    SplunkConfig,
    SysdigConfig,
)

_PROPERTY_EXTRAS: dict[str, Any] = {
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
}

#: Keys a platform block requires, besides what its model requires.
_REQUIRED: dict[type[TideModel], list[str]] = {
    # Not `scheduling`: a correlation search has nothing to schedule, so the
    # model, the deployer and the template all leave it optional.
    SplunkConfig: ["status", "query"],
    SentinelConfig: ["status", "query", "scheduling", "alert"],
    DefenderConfig: ["status", "query", "alert", "impacted_entities", "scheduling"],
    SentinelOneConfig: ["status", "condition"],
    CrowdstrikeConfig: ["status", "query", "details", "schedule"],
    HarfangLabConfig: ["status"],
    CarbonBlackConfig: ["status", "query"],
    ElasticConfig: ["status"],
    SysdigConfig: ["status"],
    BitdefenderConfig: ["status"],
    GraylogConfig: ["status", "query"],
    ExabeamConfig: ["status", "sequences"],
    GoogleSecopsConfig: ["status", "events", "condition"],
}


def platform_schema_identifiers(model: type[TideModel]) -> list[str]:
    """The ``schema`` identifiers a block of *model* accepts: its registered revision."""
    return [model.schema_identifier()]


def platform_root_extras(model: type[TideModel]) -> dict[str, Any]:
    """Return root-level schema extras for a platform configuration model.

    ``schema`` offers and accepts only the identifiers the model registers
    (``platform::splunk::1.0``), as validation does.
    """
    identifiers = platform_schema_identifiers(model)
    property_extras: dict[str, Any] = {
        **_PROPERTY_EXTRAS,
        # Keyed by the YAML key, as the schema's properties are: the model
        # field is ``platform_schema``, aliased ``schema``.
        "schema": {
            "title": "Schema identifier and version",
            # ``null`` is "left out", which validation accepts too.
            "enum": [*identifiers, None],
            "default": identifiers[-1],
        },
    }
    platform = model.schema_identifier().split("::")[1]
    property_extras["tenants"] = {
        **_PROPERTY_EXTRAS["tenants"],
        "tide.config.system.tenants": platform,
    }
    return {
        "required": list(_REQUIRED.get(model, ["status", "query"])),
        "property_extras": property_extras,
    }


def platform_model_for_key(key: str) -> type[TideModel]:
    """Resolve a platform registry key to its configuration model."""
    return PLATFORM_CONFIG_MODELS[key]
