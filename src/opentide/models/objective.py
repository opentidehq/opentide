"""Detection objective (DOM) Pydantic models — schema ``objective::1.0``."""

from __future__ import annotations

from typing import Any, ClassVar, cast

from opentide.models.base import TideModel
from opentide.models.metadata import ObjectMetadata, ObjectReferences


class SignalData(TideModel):
    availability: str
    requirements: str
    logsources: list[str] | None = None


class ExternalDetector(TideModel):
    name: str
    technology: str
    description: str
    link: str | None = None


class DetectionExample(TideModel):
    description: str
    link: str
    language: str | None = None
    query: str | None = None


class DetectionSignal(TideModel):
    """Nested detection signal within a detection objective."""

    name: str
    uuid: str
    description: str
    severity: str
    data: SignalData
    methodology: str
    entities: list[str]
    effort: int | None = None
    detectors: list[ExternalDetector] | None = None
    examples: list[DetectionExample] | None = None
    parent: str | None = None


class ObjectiveComposition(TideModel):
    strategy: str
    description: str


class ObjectiveBody(TideModel):
    priority: str
    type: str
    description: str
    signals: list[DetectionSignal]
    composition: ObjectiveComposition
    investment: str | None = None
    threats: list[str] | None = None
    attack: list[str] | None = None


class DetectionObjective(TideModel):
    """Code-first detection objective model."""

    __schema_identifier__: ClassVar[str] = "objective::1.0"

    name: str
    metadata: ObjectMetadata
    objective: ObjectiveBody
    composition: ObjectiveComposition
    references: ObjectReferences | None = None

    @classmethod
    def from_yaml_dict(cls, payload: dict[str, Any]) -> DetectionObjective:
        references = payload.get("references")
        if references is not None:
            payload = dict(payload)
            payload["references"] = ObjectReferences.coerce_public_keys(references)
        return cast(DetectionObjective, cls.model_validate(payload))
