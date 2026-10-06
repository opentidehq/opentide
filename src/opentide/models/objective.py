"""Detection objective (DOM) Pydantic models — schema ``objective::1.0``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, cast

from pydantic import model_validator

from opentide.models.base import TideField, TideModel, VocabField
from opentide.models.metadata import ObjectMetadata, ObjectReferences


class SignalData(TideModel):
    availability: str
    requirements: str
    logsources: list[str] | None = TideField(
        None,
        schema_extra={"tide.config.visibility.logsources": True},
    )


class ExternalDetector(TideModel):
    name: str
    technology: str
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    link: str | None = TideField(None, schema_extra={"format": "uri"})


class DetectionExample(TideModel):
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    link: str = TideField(schema_extra={"format": "uri"})
    language: str | None = None
    query: str | None = TideField(None, schema_extra={"tide.template.multiline": True})


class DetectionSignal(TideModel):
    """Nested detection signal within a detection objective."""

    name: str
    uuid: str
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    severity: str = VocabField("alert_severity")
    data: SignalData
    methodology: str = VocabField(True)
    entities: list[str] = VocabField(True)
    effort: int | None = None
    detectors: list[ExternalDetector] | None = None
    examples: list[DetectionExample] | None = None
    parent: str | None = None


class ObjectiveComposition(TideModel):
    strategy: str
    description: str = TideField(schema_extra={"tide.template.multiline": True})


class ObjectiveBody(TideModel):
    priority: str
    type: str
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    signals: list[DetectionSignal]
    composition: ObjectiveComposition
    investment: str | None = None
    threats: list[str] | None = None
    mitre_attack: list[str] | None = VocabField(True, default=None)


class DetectionObjective(TideModel):
    """Code-first detection objective model."""

    __schema_identifier__: ClassVar[str] = "objective::1.0"
    name: str
    metadata: ObjectMetadata = TideField(schema_extra={"tide.template.spacer": True})
    objective: ObjectiveBody
    references: ObjectReferences | None = None

    @model_validator(mode="before")
    @classmethod
    def _accept_root_composition(cls, data: Any) -> Any:
        """Ignore a root composition block. The required block is objective.composition."""
        if isinstance(data, dict) and "composition" in data:
            data = dict(data)
            data.pop("composition")
        return data

    @classmethod
    def from_yaml_dict(
        cls, payload: dict[str, Any], *, file: Path | None = None
    ) -> DetectionObjective:
        references = payload.get("references")
        if references is not None:
            payload = dict(payload)
            payload["references"] = ObjectReferences.coerce_public_keys(references)
        return cast(DetectionObjective, cls.model_validate(payload))
