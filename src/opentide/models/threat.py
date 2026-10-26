"""Threat vector (TVM) Pydantic models — schema ``threat::1.0``."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, ClassVar, cast

from pydantic import AfterValidator, Field, ValidationInfo, field_validator
from pydantic_core import PydanticCustomError

from opentide.models.base import FieldRole, TideField, TideModel, VocabField
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
    """Scoped `actors::1.0` value: `att&ck::<id>` or `misp::<id>`."""
    sighting: str | None = TideField(None, schema_extra={"tide.template.multiline": True})
    """Optional sighting note or date."""
    references: list[str] | None = None
    """Optional actor reference URLs."""


class ThreatBody(TideModel):
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    """Narrative description."""
    severity: str = VocabField(True)
    """Threat severity vocabulary (`severity::1.0`)."""
    impact: list[VocabName] = VocabField(True, min_length=1)
    """Impact vocabulary names (`impact::1.0`); non-empty."""
    leverage: list[VocabName] = VocabField(True, min_length=1)
    """Leverage vocabulary names (`leverage::1.0`); non-empty."""
    viability: str = VocabField(True)
    """Viability vocabulary (`viability::1.0`)."""
    terrain: str
    """Explanatory narrative about where/how the threat operates."""
    # `surface` keys are grouped by stage and the SAME key name legitimately
    # appears under two stages (VPN, Wireless and Industrial are each both
    # Infrastructure and Protocol). Without `scoped` those collapse to one bare
    # key and `_emit` drops the duplicate, so five values were unreachable.
    surface: list[str] = VocabField(True, scoped=True)
    """Threat surface vocabulary values (`surface::1.0`)."""
    mitre_attack: list[str] = VocabField(True, role=FieldRole.TECHNIQUES)
    """MITRE ATT&CK technique ids (`att&ck::1.2`)."""
    actors: list[ThreatActor] | None = TideField(None, role=FieldRole.ACTORS)
    """Threat actors attributed to this vector."""
    killchain: str | list[str] | None = VocabField(True, default=None)
    """Kill chain stage(s)."""
    chaining: list[dict[str, str]] | None = None
    """Vector chaining relationships."""
    cve: list[str] | None = Field(default=None, title="CVE")
    """CVE identifiers the threat exploits (`CVE-2024-3400`)."""

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
    """Threat vector display name."""
    criticality: str = VocabField(True)
    """Criticality vocabulary value."""
    metadata: ObjectMetadata = TideField(schema_extra={"tide.template.spacer": True})
    """Object metadata: identifier, schema, version, dates and TLP."""
    threat: ThreatBody
    """Threat assessment body."""
    references: ObjectReferences | None = None
    """External and internal references."""

    @classmethod
    def from_yaml_dict(cls, payload: dict[str, Any], *, file: Path | None = None) -> ThreatVector:
        references = payload.get("references")
        if references is not None:
            payload = dict(payload)
            payload["references"] = ObjectReferences.coerce_public_keys(references)
        return cast(ThreatVector, cls.model_validate(payload))
