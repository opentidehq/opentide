"""Threat vector (TVM) Pydantic models — schema ``threat::1.0``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, cast

from pydantic import Field, model_validator

from opentide.models.base import TideModel, VocabField
from opentide.models.metadata import ObjectMetadata, ObjectReferences


class ThreatBody(TideModel):
    description: str
    severity: str = VocabField(True)
    impact: str = VocabField(True)
    leverage: str = VocabField(True)
    viability: str = VocabField(True)
    terrain: list[str] = VocabField(True)
    att_ck: list[str] = Field(alias="att&ck", json_schema_extra={"tide.vocab": True})
    actors: list[str] | None = VocabField(True, default=None)
    killchain: str | list[str] | None = VocabField(True, default=None)
    chaining: list[dict[str, str]] | None = None

    @model_validator(mode="before")
    @classmethod
    def _accept_attack_key(cls, data: Any) -> Any:
        if isinstance(data, dict) and "att&ck" in data and ("att_ck" not in data):
            data = dict(data)
            data["att_ck"] = data.pop("att&ck")
        return data


class ThreatVector(TideModel):
    """Code-first threat vector model (replaces raw TVM dict entries)."""

    __schema_identifier__: ClassVar[str] = "threat::1.0"
    name: str
    criticality: str = VocabField(True)
    metadata: ObjectMetadata
    threat: ThreatBody
    references: ObjectReferences | None = None

    @classmethod
    def from_yaml_dict(cls, payload: dict[str, Any], *, file: Path | None = None) -> ThreatVector:
        references = payload.get("references")
        if references is not None:
            payload = dict(payload)
            payload["references"] = ObjectReferences.coerce_public_keys(references)
        return cast(ThreatVector, cls.model_validate(payload))


class ThreatVector_v2_1(ThreatVector):
    """Threat vector schema revision ``threat::2.1`` (structure unchanged; pin bump only)."""

    __schema_identifier__: ClassVar[str] = "threat::2.1"
