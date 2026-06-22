"""Pydantic code-first models for OpenTide objects."""

from opentide.models.base import TideField, TideModel, field_json_schema_extra
from opentide.models.enums import EnumEntry, EnumRegistry
from opentide.models.metadata import ObjectMetadata, ObjectReferences, Organisation
from opentide.models.objective import (
    DetectionExample,
    DetectionObjective,
    DetectionSignal,
    ExternalDetector,
    ObjectiveBody,
    ObjectiveComposition,
    SignalData,
)
from opentide.models.results import DeploymentResult, ValidationResult
from opentide.models.rule import DetectionRule, TideRegistry
from opentide.models.threat import ThreatBody, ThreatVector
from opentide.models.version import SchemaVersion, SchemaVersionChain

__all__ = [
    "DeploymentResult",
    "DetectionExample",
    "DetectionObjective",
    "DetectionRule",
    "DetectionSignal",
    "EnumEntry",
    "EnumRegistry",
    "ExternalDetector",
    "ObjectiveBody",
    "ObjectiveComposition",
    "ObjectMetadata",
    "ObjectReferences",
    "Organisation",
    "SchemaVersion",
    "SchemaVersionChain",
    "SignalData",
    "ThreatBody",
    "ThreatVector",
    "TideField",
    "TideModel",
    "TideRegistry",
    "ValidationResult",
    "field_json_schema_extra",
]
