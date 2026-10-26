"""Results of the commands that read the catalogue, and of explain and commands."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from opentide.cli.ui.results.base import (
    CommandDocument,
    Counts,
    DiagnosticFields,
    ResultModel,
    ValidationReportModel,
)

# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------


class CheckVerdict(ResultModel):
    """One check's verdict."""

    check: str
    status: Literal["passed", "failed"]


class FixedValue(ResultModel):
    """One value a safe fix replaces."""

    path: str
    line: int
    code: str
    before: str
    after: str


class ValidateSummary(ResultModel):
    objects: int = Field(0, description="Objects checked")
    errors: int = 0
    warnings: int = 0
    files: int = Field(0, description="Files with an error")
    warning_files: int = Field(0, description="Files with a warning")
    # From validate --fix (#646), declared ahead so either merge order stays green.
    fixable: int = Field(0, description="Findings a safe fix resolves")
    fixed: int = Field(0, description="With --fix: values replaced")


class ValidateResult(CommandDocument):
    """``opentide validate``: every check's verdict and the full report."""

    checks: dict[str, CheckVerdict] = Field(
        default_factory=dict, description="Verdict by check name"
    )
    report: ValidationReportModel | None = Field(
        None, description="Issues (errors) and warnings, with diagnostic fields"
    )
    check: str | None = Field(None, description="The check selected with --check")
    workspace: str | None = Field(None, description="The workspace that was validated")
    # From validate --fix (#646).
    fixed: list[FixedValue] | None = Field(None, description="With --fix: the values replaced")
    would_fix: list[FixedValue] | None = Field(
        None, description="With --fix --dry-run: the values --fix would replace"
    )
    diff: str | None = Field(None, description="With --fix --dry-run: a unified diff")
    summary: ValidateSummary


class QueryValidationResult(CommandDocument):
    """``opentide validate query``: one platform's queries checked on its tenants."""

    platform: str | None = None
    mode: Literal["live"] | None = None
    supported: bool | None = Field(None, description="Whether the platform has query validation")
    valid: None = Field(None, description="null when the platform has no query validation")
    platform_enabled: bool | None = None
    strategies: list[str] = Field(default_factory=list, description="The run's strategies")
    queries_validated: int | None = None
    queries_per_tenant: dict[str, int] = Field(
        default_factory=dict, description="Queries sent, by tenant"
    )
    scope: Literal["changed", "selected"] | None = Field(
        None, description="The narrowed rule scope, when --changed, --file or --uuid narrowed it"
    )
    unmatched: list[str] = Field(
        default_factory=list, description="--file or --uuid values that matched no rule"
    )
    tenant: str | None = Field(None, description="The tenant that could not be reached")
    host: str | None = None
    missing_tenants: dict[str, str] = Field(
        default_factory=dict, description="Platform configuration files with no tenant"
    )
    advice: str | None = None


# --------------------------------------------------------------------------
# lint
# --------------------------------------------------------------------------


class LintFinding(DiagnosticFields):
    """One lint finding, with the diagnostic fields."""

    check: str
    severity: Literal["error", "warning", "info"]
    path: str = Field(description="Workspace-relative path")
    yaml_line: int | None = Field(description="0-based")
    uuid: str | None
    expected: str | None = Field(None, description="The file name the object's name derives")
    fixed: bool | None = Field(None, description="true when --fix renamed the file")
    from_: str | None = Field(
        None, alias="from", description="The file's previous path, when --fix renamed it"
    )
    note: str | None = None


class LintSummary(ResultModel):
    files: int = 0
    findings: int = 0
    errors: int = 0
    warnings: int = 0
    notes: int = 0
    fixed: int = 0


class LintResult(CommandDocument):
    """``opentide lint``: catalogue hygiene findings."""

    path: str | None = None
    checks: list[str] = Field(default_factory=list)
    findings: list[LintFinding] = Field(default_factory=list)
    count: int | None = None
    fixed: int | None = None
    summary: LintSummary


# --------------------------------------------------------------------------
# info
# --------------------------------------------------------------------------


class PlatformInfo(ResultModel):
    name: str
    enabled: bool
    can_deploy: bool
    can_validate: bool


class TechniqueCoverage(ResultModel):
    technique: str
    rules: list[str] = Field(description="UUIDs of the rules that cover the technique")
    count: int


class InfoSummary(ResultModel):
    rules: int = 0
    threats: int = 0
    objectives: int = 0
    load_errors: int = 0


class InfoResult(CommandDocument):
    """``opentide info``: version, object counts and platforms."""

    version: str | None = None
    repo: str | None = None
    counts: Counts | None = None
    parse_error_count: int | None = None
    platforms: list[PlatformInfo] = Field(default_factory=list)
    rules: list[str] | None = Field(None, description="Rule UUIDs, for the rules section")
    threats: list[str] | None = Field(None, description="Threat UUIDs, for the threats section")
    objectives: list[str] | None = Field(
        None, description="Objective UUIDs, for the objectives section"
    )
    coverage: TechniqueCoverage | None = Field(None, description="For the coverage section")
    summary: InfoSummary


# --------------------------------------------------------------------------
# rules unreviewed
# --------------------------------------------------------------------------


class UnreviewedRule(ResultModel):
    path: str
    schema_: str = Field(alias="schema")
    reason: str
    reviewed: str | None


class UnreviewedResult(CommandDocument):
    """``opentide rules unreviewed``: rules due for review."""

    evaluated_at: str | None = None
    window: str | None = None
    count: int | None = None
    rules: list[UnreviewedRule] = Field(default_factory=list)


# --------------------------------------------------------------------------
# explain
# --------------------------------------------------------------------------


class CodeMeaning(ResultModel):
    code: str
    meaning: str


class ExplainResult(CommandDocument):
    """``opentide explain``: one code's page, or every code with no argument."""

    code: str | None = None
    meaning: str | None = None
    markdown: str | None = None
    codes: list[CodeMeaning] | None = Field(None, description="Every code, with no argument")


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


class ParameterInfo(ResultModel):
    name: str | None
    type: str
    choices: list[Any] | None
    default: Any
    required: bool
    multiple: bool
    envvars: list[str]
    help: str | None


class OptionInfo(ParameterInfo):
    flags: list[str]
    secondary_flags: list[str]
    is_flag: bool


class CommandInfo(ResultModel):
    path: str
    name: str
    summary: str
    help: str
    group: bool
    runs_alone: bool
    subcommands: list[str]
    deprecated: bool
    arguments: list[ParameterInfo]
    options: list[OptionInfo]
    example: str
    output_schema: dict[str, Any] | None = Field(
        description="The JSON Schema of the command's --json document; null when it prints none"
    )


class CommandsSummary(ResultModel):
    commands: int = 0
    groups: int = 0


class EnvironmentVariable(ResultModel):
    name: str
    meaning: str


class CommandsResult(CommandDocument):
    """``opentide commands``: the command tree, with each command's output schema."""

    program: str
    version: str = Field(description="The installed opentide version")
    global_options: list[OptionInfo]
    environment: list[EnvironmentVariable] = Field(
        description="Variables that change every command but are not options"
    )
    commands: list[CommandInfo]
    defs: dict[str, Any] = Field(
        alias="$defs", description="The schemas each output_schema refers to"
    )
    summary: CommandsSummary
