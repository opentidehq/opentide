"""Pydantic code-first models for opentide objects."""

from opentide._models.base import TideField, TideModel, field_json_schema_extra
from opentide._models.enums import EnumEntry, EnumRegistry
from opentide._models.metadata import ObjectMetadata, ObjectReferences, Organisation
from opentide._models.object_types import (
    CORE_OBJECT_TYPES,
    OBJECTIVE,
    RULE,
    SIGNAL,
    THREAT,
    latest_identifier,
)
from opentide._models.objective import (
    DetectionExample,
    DetectionObjective,
    DetectionSignal,
    ExternalDetector,
    ObjectiveBody,
    ObjectiveComposition,
    SignalData,
)
from opentide._models.results import DeploymentResult, ValidationResult
from opentide._models.rule import DetectionRule, TideRegistry
from opentide._models.threat import ThreatActor, ThreatBody, ThreatVector
from opentide._models.version import SchemaVersion, SchemaVersionChain

__all__ = [
    "CORE_OBJECT_TYPES",
    "OBJECTIVE",
    "RULE",
    "SIGNAL",
    "THREAT",
    "DeploymentResult",
    "DetectionExample",
    "DetectionObjective",
    "DetectionRule",
    "DetectionSignal",
    "EnumEntry",
    "EnumRegistry",
    "ExternalDetector",
    "ObjectMetadata",
    "ObjectReferences",
    "ObjectiveBody",
    "ObjectiveComposition",
    "Organisation",
    "SchemaVersion",
    "SchemaVersionChain",
    "SignalData",
    "ThreatActor",
    "ThreatBody",
    "ThreatVector",
    "TideField",
    "TideModel",
    "TideRegistry",
    "ValidationResult",
    "field_json_schema_extra",
    "latest_identifier",
]
