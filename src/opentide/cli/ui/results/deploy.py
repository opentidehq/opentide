"""Results of ``opentide deploy`` and ``deploy migrate-state``."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from opentide.cli.ui.results.base import CommandDocument, ResultModel


class RulePayload(ResultModel):
    """The request a dry run would send for one rule."""

    uuid: str
    name: str
    api_request: dict[str, Any] | None = Field(
        description="The vendor API body; null when the rule could not be compiled"
    )
    status: str | None = Field(None, description="failed, when the rule could not be compiled")
    error: str | None = None
    # A rule the dry run could not compile (#643): the diagnostic's own fields.
    code: str | None = Field(None, description="compile_* code, when the rule could not compile")
    help: str | None = Field(None, description="What fixes it, when known")
    file: str | None = Field(None, description="The rule's file, absolute")


class CompileDiagnostic(ResultModel):
    """A rule a dry run could not compile, as one diagnostic (#643)."""

    code: str = Field(description="compile_missing_field, compile_empty_block, …")
    severity: Literal["error", "warning"]
    message: str | None
    help: str | None
    path: str | None = Field(description="Workspace-relative; null outside the workspace")
    file_path: str | None = Field(description="Absolute")
    platform: str
    uuid: str | None
    name: str | None


class PlannedChange(ResultModel):
    """What a deploy does, or would do, to one rule on one tenant (#643)."""

    platform: str
    tenant: str | None = Field(description="null when the platform has no tenant configured yet")
    uuid: str
    name: str
    status: str
    action: Literal["create", "update", "upsert", "disable", "delete"]


class DeployResult(CommandDocument):
    """``opentide deploy``: the plan, and what was deployed or would be."""

    deployed: list[str] | None = Field(None, description="Platforms deployed to")
    dry_run: bool | None = None
    plan: dict[str, list[str]] | None = Field(None, description="Rule UUIDs by platform")
    strategies: list[str] | None = Field(None, description="The run's strategies")
    payloads: dict[str, list[RulePayload]] | None = Field(
        None, description="Dry run: the request for each rule, by platform"
    )
    tenants: dict[str, dict[str, list[str]]] | None = Field(
        None, description="Dry run: rule UUIDs by platform and tenant"
    )
    missing_tenants: dict[str, str] | None = Field(
        None, description="Platform configuration files with no tenant, by platform"
    )
    platform: str | None = Field(None, description="The platform selected with --platform")
    advice: str | None = None
    # Added by #643 (flow), declared ahead so either merge order stays green.
    changes: list[PlannedChange] | None = Field(None, description="One entry per rule and tenant")
    diagnostics: list[CompileDiagnostic] | None = Field(
        None, description="Dry run: one entry per rule that would fail to compile"
    )


class StateBinding(ResultModel):
    platform: str
    tenant: str
    external_id: str


class MigratedRule(ResultModel):
    file: str
    uuid: str
    shard: str | None = Field(description="The deployment state shard written")
    bindings: list[StateBinding]
    removed: list[str] = Field(description="Keys removed from the rule")


class UnusedId(StateBinding):
    """A vendor id removed from a rule and not stored: its deployer never reads it."""

    file: str
    uuid: str


class MigrateStateError(ResultModel):
    code: str
    file: str
    uuid: str
    message: str


class GitignoreRule(ResultModel):
    pattern: str
    source: str
    line: int


class MigrateStateResult(CommandDocument):
    """``opentide deploy migrate-state``: vendor ids moved into deployment state."""

    migrated: list[MigratedRule] = Field(default_factory=list)
    unused: list[UnusedId] = Field(default_factory=list)
    errors: list[MigrateStateError] = Field(default_factory=list)
    shards_written: int | None = None
    rules_edited: int | None = None
    code: str | None = Field(None, description="deployment_state_ignored, when refused")
    ignore: GitignoreRule | None = Field(
        None, description="The .gitignore rule that hides deployment state"
    )
    advice: str | None = None
    detail: str | None = None
