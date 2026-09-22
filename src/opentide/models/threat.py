"""Threat vector (TVM) Pydantic models — schema ``threat::1.0``."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, ClassVar, cast

from pydantic import AfterValidator, Field, ValidationInfo, field_validator, model_validator
from pydantic_core import PydanticCustomError

from opentide.models.base import TideField, TideModel, VocabField
from opentide.models.metadata import ObjectMetadata, ObjectReferences


def _single_vocab_name(value: str) -> str:
    # threat-1.0 forbids semicolon packing as a multi-value encoding, and forbids
    # recovering from it by keeping only the first token.
    if ";" in value:
        raise PydanticCustomError(
            "vocab_packed_names",
            "'{value}' packs several vocabulary names into one string; "
            "list each name as its own item",
            {"value": value},
        )
    return value


VocabName = Annotated[str, AfterValidator(_single_vocab_name)]


class ThreatActor(TideModel):
    """One attributed actor on a threat vector (CoreTide ``actors`` definition)."""

    name: str = VocabField("actors", scoped=True)
    sighting: str | None = TideField(None, schema_extra={"tide.template.multiline": True})
    references: list[str] | None = None


class ThreatBody(TideModel):
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    severity: str = VocabField(True)
    impact: list[VocabName] = VocabField(True, min_length=1)
    leverage: list[VocabName] = VocabField(True, min_length=1)
    viability: str = VocabField(True)
    terrain: str
    surface: list[str] = VocabField(True)
    att_ck: list[str] = Field(alias="att&ck", json_schema_extra={"tide.vocab": True})
    actors: list[ThreatActor] | None = None
    killchain: str | list[str] | None = VocabField(True, default=None)
    chaining: list[dict[str, str]] | None = None
    cve: list[str] | None = Field(default=None, title="CVE")

    @model_validator(mode="before")
    @classmethod
    def _accept_attack_key(cls, data: Any) -> Any:
        if isinstance(data, dict) and "att&ck" in data and ("att_ck" not in data):
            data = dict(data)
            data["att_ck"] = data.pop("att&ck")
        return data

    @field_validator("impact", "leverage", mode="before")
    @classmethod
    def _require_vocab_list(cls, value: Any, info: ValidationInfo) -> Any:
        if isinstance(value, str):
            message = "must be a YAML list of {field} vocabulary names, not a single string"
            if ";" in value:
                message += "; list each name in '{value}' as its own item"
            raise PydanticCustomError(
                "vocab_list_type", message, {"field": info.field_name, "value": value}
            )
        return value


class ThreatVector(TideModel):
    """Code-first threat vector model (replaces raw TVM dict entries)."""

    __schema_identifier__: ClassVar[str] = "threat::1.0"
    name: str
    criticality: str = VocabField(True)
    metadata: ObjectMetadata = TideField(schema_extra={"tide.template.spacer": True})
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
