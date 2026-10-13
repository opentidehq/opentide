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
    # `responders` is a CONFIGURATION ENUM, not a vocabulary. The alert
    # handling team is per-organisation, so the allowed values come from
    # `[[responders]]` in deployment.toml rather than from a canonical
    # upstream vocabulary. An instance that declares none leaves the field
    # unconstrained -- a validated field bound to an empty shipped list is
    # exactly what no instance could satisfy (#507).
    responders: str | None = TideField(None, schema_extra={"tide.config.responders": True})
    procedure: ResponseProcedure | None = None
