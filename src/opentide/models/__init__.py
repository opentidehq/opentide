"""The Tide models: frozen Rust classes under their Pydantic names (UC-1.9, ADR 0011).

``from opentide.models import DetectionRule`` gives the Rust model compiled into
opentide (``opentide._native.models``): ``model_validate``, ``model_dump``,
``model_copy``, ``model_json_schema``, field access, equality, hashing and
pickling, as the Pydantic models had them. ``opentide.models.delegation`` holds
the helpers the Pydantic rule had as methods (``validate``, ``deploy``,
``document``, ``from_yaml_dict``, …).

Importing this package loads neither Pydantic nor the Pydantic package the CLI
still runs on (``opentide._models``). Its other names keep working: the result
models and object-type constants as they were, the Pydantic machinery
(``TideModel``, ``TideField``, …) with a ``DeprecationWarning``, and a submodule
this package does not define (``opentide.models.results``,
``opentide.models.configuration``, …) is the Pydantic package's.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentide._native.models import (
    CarbonBlackConfig,
    CrowdstrikeConfig,
    CrowdstrikeDetails,
    CrowdstrikeSchedule,
    DefenderAlert,
    DefenderAllowBlockAction,
    DefenderAllowBlockGroupScoping,
    DefenderConfig,
    DefenderDeviceActions,
    DefenderExclusion,
    DefenderFileActions,
    DefenderGroupScoping,
    DefenderImpactedEntities,
    DefenderResponseActions,
    DefenderUserActions,
    DetectionExample,
    DetectionObjective,
    DetectionRule,
    DetectionRule_v1_1,
    DetectionSignal,
    ElasticActions,
    ElasticCardinality,
    ElasticConfig,
    ElasticEql,
    ElasticExceptionList,
    ElasticExceptions,
    ElasticFilter,
    ElasticGuide,
    ElasticIntegration,
    ElasticMachineLearning,
    ElasticNewTerms,
    ElasticOverrides,
    ElasticRequiredField,
    ElasticRisk,
    ElasticRiskScoreMapping,
    ElasticScheduling,
    ElasticSeverity,
    ElasticSeverityMapping,
    ElasticSuppression,
    ElasticThreatEntry,
    ElasticThreatGroup,
    ElasticThreatMatch,
    ElasticThreshold,
    ElasticTimeline,
    ExternalDetector,
    HarfangLabConfig,
    HarfangLabSigma,
    HarfangLabSigmaLogSource,
    HarfangLabSigmaSelection,
    HarfangLabYara,
    HarfangLabYaraMeta,
    ObjectiveBody,
    ObjectiveComposition,
    ObjectMetadata,
    ObjectReferences,
    Organisation,
    ResponseProcedure,
    ResponseSearch,
    RuleConfigurations,
    RuleMetadata,
    RuleResponse,
    SentinelAlert,
    SentinelAlertGrouping,
    SentinelConfig,
    SentinelCustomDetails,
    SentinelDynamicProperties,
    SentinelEntityMapping,
    SentinelExclusion,
    SentinelGrouping,
    SentinelMappingEntry,
    SentinelOneCondition,
    SentinelOneConfig,
    SentinelOneCorrelation,
    SentinelOneDetails,
    SentinelOneResponse,
    SentinelOneSingleEvent,
    SentinelOneSubQuery,
    SentinelScheduling,
    SentinelTemplate,
    SentinelTrigger,
    SignalData,
    SplunkActions,
    SplunkConfig,
    SplunkEmail,
    SplunkEmailInclude,
    SplunkNotable,
    SplunkNotableDrilldown,
    SplunkNotableEvent,
    SplunkRisk,
    SplunkRiskObject,
    SplunkSchedule,
    SplunkScheduling,
    SplunkThreatObject,
    SplunkThrottling,
    SplunkTimerange,
    SplunkTrigger,
    SysdigConfig,
    SysdigException,
    SysdigList,
    SysdigMacro,
    ThreatActor,
    ThreatBody,
    ThreatVector,
    ValidationError,
)
from opentide.models import _compat

if TYPE_CHECKING:
    from opentide._models.enums import EnumEntry, EnumRegistry
    from opentide._models.object_types import (
        CORE_OBJECT_TYPES,
        OBJECTIVE,
        RULE,
        SIGNAL,
        THREAT,
        latest_identifier,
    )
    from opentide._models.results import DeploymentResult, ValidationResult
    from opentide._models.version import SchemaVersion, SchemaVersionChain

_compat.install()

__all__ = [
    "CORE_OBJECT_TYPES",
    "OBJECTIVE",
    "RULE",
    "SIGNAL",
    "THREAT",
    "CarbonBlackConfig",
    "CrowdstrikeConfig",
    "CrowdstrikeDetails",
    "CrowdstrikeSchedule",
    "DefenderAlert",
    "DefenderAllowBlockAction",
    "DefenderAllowBlockGroupScoping",
    "DefenderConfig",
    "DefenderDeviceActions",
    "DefenderExclusion",
    "DefenderFileActions",
    "DefenderGroupScoping",
    "DefenderImpactedEntities",
    "DefenderResponseActions",
    "DefenderUserActions",
    "DeploymentResult",
    "DetectionExample",
    "DetectionObjective",
    "DetectionRule",
    "DetectionRule_v1_1",
    "DetectionSignal",
    "ElasticActions",
    "ElasticCardinality",
    "ElasticConfig",
    "ElasticEql",
    "ElasticExceptionList",
    "ElasticExceptions",
    "ElasticFilter",
    "ElasticGuide",
    "ElasticIntegration",
    "ElasticMachineLearning",
    "ElasticNewTerms",
    "ElasticOverrides",
    "ElasticRequiredField",
    "ElasticRisk",
    "ElasticRiskScoreMapping",
    "ElasticScheduling",
    "ElasticSeverity",
    "ElasticSeverityMapping",
    "ElasticSuppression",
    "ElasticThreatEntry",
    "ElasticThreatGroup",
    "ElasticThreatMatch",
    "ElasticThreshold",
    "ElasticTimeline",
    "EnumEntry",
    "EnumRegistry",
    "ExternalDetector",
    "HarfangLabConfig",
    "HarfangLabSigma",
    "HarfangLabSigmaLogSource",
    "HarfangLabSigmaSelection",
    "HarfangLabYara",
    "HarfangLabYaraMeta",
    "ObjectMetadata",
    "ObjectReferences",
    "ObjectiveBody",
    "ObjectiveComposition",
    "Organisation",
    "ResponseProcedure",
    "ResponseSearch",
    "RuleConfigurations",
    "RuleMetadata",
    "RuleResponse",
    "SchemaVersion",
    "SchemaVersionChain",
    "SentinelAlert",
    "SentinelAlertGrouping",
    "SentinelConfig",
    "SentinelCustomDetails",
    "SentinelDynamicProperties",
    "SentinelEntityMapping",
    "SentinelExclusion",
    "SentinelGrouping",
    "SentinelMappingEntry",
    "SentinelOneCondition",
    "SentinelOneConfig",
    "SentinelOneCorrelation",
    "SentinelOneDetails",
    "SentinelOneResponse",
    "SentinelOneSingleEvent",
    "SentinelOneSubQuery",
    "SentinelScheduling",
    "SentinelTemplate",
    "SentinelTrigger",
    "SignalData",
    "SplunkActions",
    "SplunkConfig",
    "SplunkEmail",
    "SplunkEmailInclude",
    "SplunkNotable",
    "SplunkNotableDrilldown",
    "SplunkNotableEvent",
    "SplunkRisk",
    "SplunkRiskObject",
    "SplunkSchedule",
    "SplunkScheduling",
    "SplunkThreatObject",
    "SplunkThrottling",
    "SplunkTimerange",
    "SplunkTrigger",
    "SysdigConfig",
    "SysdigException",
    "SysdigList",
    "SysdigMacro",
    "ThreatActor",
    "ThreatBody",
    "ThreatVector",
    "ValidationError",
    "ValidationResult",
    "latest_identifier",
]

#: Names that are not Tide models, kept as they were: read from the Pydantic
#: package's module on first use.
_KEPT: dict[str, str] = {
    "CORE_OBJECT_TYPES": "object_types",
    "OBJECTIVE": "object_types",
    "RULE": "object_types",
    "SIGNAL": "object_types",
    "THREAT": "object_types",
    "latest_identifier": "object_types",
    "DeploymentResult": "results",
    "ValidationResult": "results",
    "EnumEntry": "enums",
    "EnumRegistry": "enums",
    "SchemaVersion": "version",
    "SchemaVersionChain": "version",
}
#: The Pydantic machinery, kept for one minor release with a warning.
_DEPRECATED: dict[str, str] = {
    "TideField": "base",
    "TideModel": "base",
    "field_json_schema_extra": "base",
    "TideRegistry": "rule",
}


def __getattr__(name: str) -> object:
    """A kept or deprecated name, read once: ``from opentide.models import
    TideModel`` looks the name up twice, and warns once."""
    if name in _KEPT:
        import importlib

        value = getattr(importlib.import_module(f"opentide._models.{_KEPT[name]}"), name)
    elif name in _DEPRECATED:
        value = _compat.deprecated_attribute(
            __name__, f"opentide._models.{_DEPRECATED[name]}", name
        )
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
