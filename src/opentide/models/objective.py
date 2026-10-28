"""Detection objective (DOM) Pydantic models — schema ``objective::1.0``."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar, cast

from pydantic import StrictInt, model_validator

from opentide.models.base import FieldRole, TideField, TideModel, VocabField
from opentide.models.metadata import ObjectMetadata, ObjectReferences


class SignalData(TideModel):
    availability: str
    """Data availability level."""
    requirements: str
    """Data source requirements."""
    logsources: list[str] | None = TideField(
        None,
        schema_extra={"tide.config.visibility.logsource-names": True},
    )
    """Log source names from the workspace `visibility.toml`."""


class ExternalDetector(TideModel):
    name: str
    """Detector name."""
    technology: str
    """Technology identifier."""
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    """Detector description."""
    link: str | None = TideField(None, schema_extra={"format": "uri"})
    """Reference URL."""


class DetectionExample(TideModel):
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    """Example description."""
    link: str = TideField(schema_extra={"format": "uri"})
    """Example URL."""
    language: str | None = None
    """Query language."""
    query: str | None = TideField(None, schema_extra={"tide.template.multiline": True})
    """Example query text."""


class DetectionSignal(TideModel):
    """Nested detection signal within a detection objective."""

    name: str
    """Signal name."""
    uuid: str
    """Signal UUID."""
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    """Signal description."""
    severity: str = VocabField("alert_severity")
    """Alert severity vocabulary (`alert_severity::1.0`)."""
    data: SignalData
    """Data availability and requirements."""
    methodology: str = VocabField(True)
    """Detection methodology vocabulary."""
    # `signal.entities` keys are grouped by stage and the SAME key name
    # legitimately appears under two stages (Account, User, Email, Token,
    # Authentication, Permissions and API Call are each both Host and Cloud,
    # or Network and one of them). Without `scoped` those collapse to one bare
    # key and `_emit` drops the duplicate, so seven values were unreachable and
    # a host account could not be told apart from a cloud account.
    entities: list[str] = VocabField(True, scoped=True)
    """Signal entity vocabulary values, stage-scoped (`signal.entities::1.0`; e.g. `Host::Process`,
    `Cloud::Account`)."""
    # Strict, so `opentide validate` and the editor schema (`type: integer`)
    # reject the same values: no quoted numbers or booleans.
    effort: StrictInt | None = None
    """Implementation effort of the signal, a score from `1` (lowest) to `10` (highest). Values
    SHOULD be within that range. Not a vocabulary term."""
    detectors: list[ExternalDetector] | None = None
    """External detector references."""
    examples: list[DetectionExample] | None = None
    """Example queries."""
    parent: str | None = None
    """Parent signal UUID."""


class ObjectiveComposition(TideModel):
    strategy: str
    """Detection composition strategy vocabulary."""
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    """How signals compose."""


class ObjectiveBody(TideModel):
    priority: str
    """Priority level."""
    type: str
    """Detection type vocabulary."""
    description: str = TideField(schema_extra={"tide.template.multiline": True})
    """Objective narrative."""
    signals: list[DetectionSignal]
    """Detection signals. At least one."""
    composition: ObjectiveComposition
    """Nested composition (same semantics as top-level)."""
    investment: str | None = None
    """Investment level."""
    threats: list[str] | None = None
    """Threat vector UUIDs."""
    mitre_attack: list[str] | None = VocabField(True, default=None, role=FieldRole.TECHNIQUES)
    """ATT&CK technique ids (`att&ck::1.2`)."""


class DetectionObjective(TideModel):
    """Code-first detection objective model."""

    __schema_identifier__: ClassVar[str] = "objective::1.0"
    # A root composition block is accepted and dropped: the required one is
    # objective.composition.
    __legacy_keys__: ClassVar[Mapping[str, str | None]] = {"composition": None}
    name: str
    """Objective display name."""
    metadata: ObjectMetadata = TideField(schema_extra={"tide.template.spacer": True})
    """Object metadata: identifier, schema, version, dates and TLP."""
    objective: ObjectiveBody
    """Detection objective body."""
    references: ObjectReferences | None = None
    """External and internal references."""

    @model_validator(mode="before")
    @classmethod
    def _accept_root_composition(cls, data: Any) -> Any:
        """Ignore a root composition block. The required block is objective.composition."""
        if isinstance(data, dict):
            dropped = [key for key, fills in cls.__legacy_keys__.items() if fills is None]
            if any(key in data for key in dropped):
                data = {key: value for key, value in data.items() if key not in dropped}
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
