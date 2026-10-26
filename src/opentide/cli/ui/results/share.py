"""Results of ``opentide share`` and its subcommands."""

from __future__ import annotations

from pydantic import Field

from opentide.cli.ui.results.base import CommandDocument, ResultModel


class ShareRecordModel(ResultModel):
    """One object on one sharing target."""

    object_uuid: str
    integration: str
    target: str
    action: str = Field(description="What happened, or would happen, to the object")
    remote_event_uuid: str | None = None
    remote_event_id: int | None = None
    reason: str | None = None
    notes: list[str] | None = None


class ShareResult(CommandDocument):
    """``share push``, ``preview``, ``status`` and ``retract``: one record per object and target."""

    records: list[ShareRecordModel] | None = None
    preflight: str | None = Field(
        None, description="The check that stopped the run before any request"
    )
    issues: list[str] | None = Field(None, description="Why sharing.toml failed validation")


class ShareTarget(ResultModel):
    integration: str
    name: str
    enabled: bool
    max_tlp: str
    url: str


class ShareTargetsResult(CommandDocument):
    """``share targets``: the sharing destinations. The API key is never printed."""

    targets: list[ShareTarget] | None = None
    preflight: str | None = None
    issues: list[str] | None = Field(None, description="Why sharing.toml failed validation")
