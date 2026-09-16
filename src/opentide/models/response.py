"""Detection rule response block models."""

from __future__ import annotations

from opentide.models.base import TideField, TideModel


class ResponseSearch(TideModel):
    purpose: str
    system: str
    query: str = TideField(schema_extra={"tide.template.multiline": True})


class ResponseProcedure(TideModel):
    analysis: str = TideField(schema_extra={"tide.template.multiline": True})
    searches: list[ResponseSearch] | None = None
    containment: str | None = None


class RuleResponse(TideModel):
    alert_severity: str = "Informational"
    playbook: str | None = None
    responders: str | None = None
    procedure: ResponseProcedure | None = None
