"""Detection rule response block models."""

from __future__ import annotations

from opentide.models.base import TideField, TideModel


class ResponseSearch(TideModel):
    purpose: str
    """Why this search is run."""
    system: str
    """Target platform or system."""
    query: str = TideField(schema_extra={"tide.template.multiline": True})
    """Query text."""


class ResponseProcedure(TideModel):
    analysis: str = TideField(schema_extra={"tide.template.multiline": True})
    """Analysis steps narrative."""
    searches: list[ResponseSearch] | None = None
    """Supplemental hunt searches."""
    containment: str | None = None
    """Containment guidance."""


class RuleResponse(TideModel):
    alert_severity: str = "Informational"
    """Alert severity vocabulary."""
    playbook: str | None = None
    """Playbook identifier or URL."""
    # `responders` is a CONFIGURATION ENUM, not a vocabulary. The alert
    # handling team is per-organisation, so the allowed values come from
    # `[[responders]]` in deployment.toml rather than from a canonical
    # upstream vocabulary. An instance that declares none leaves the field
    # unconstrained -- a validated field bound to an empty shipped list is
    # exactly what no instance could satisfy (#507).
    responders: str | None = TideField(None, schema_extra={"tide.config.responders": True})
    """Alert-handling team. Free text, not a vocabulary: teams are configured per organisation in
    `deployment.toml`."""
    procedure: ResponseProcedure | None = None
    """Analysis and containment procedure."""
