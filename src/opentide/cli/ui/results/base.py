"""The envelope every ``--json`` document carries, and the shapes commands share.

A command's result model subclasses :class:`CommandDocument` and adds the
keys of its own payload. Every model allows keys it does not name: the JSON
contract is additive, so a reader must accept a key it does not know. The
test suite is stricter and fails on a key no model names (see
``tests/result_models_support.py``), which keeps the models complete.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ResultModel(BaseModel):
    """Base of every typed result. Unknown keys are allowed, as the contract is additive."""

    model_config = ConfigDict(extra="allow")


class NextActionModel(ResultModel):
    """A command worth running next, and why."""

    command: str = Field(description="The command line to run")
    reason: str = Field(description="Why to run it; empty when it says nothing more")


class FailureModel(ResultModel):
    """Why a command did not exit 0."""

    code: str = Field(description="Stable snake_case code to branch on")
    message: str = Field(description="The error message")
    argument: str | None = Field(description="The input at fault, when one is")
    suggestion: str | None = Field(description="The closest valid value, when one is close")
    crash_log: str | None = Field(description="Reserved for unexpected errors")


class CommandDocument(ResultModel):
    """The keys every ``--json`` document carries, next to the command's own."""

    ok: bool = Field(description="false when the command failed")
    status: str = Field(description="completed, passed, issues, skipped or failed")
    message: str = Field(description="The outcome in one sentence")
    error: str | None = Field(None, description="On a failure: the error message")
    warnings: list[str] = Field(
        default_factory=list, description="Present when the command has warnings"
    )
    schema_version: Literal[1] = Field(description="Version of the envelope")
    command: str = Field(description="The command that ran, such as 'validate query'")
    duration_ms: int = Field(description="Wall time of the command")
    exit_code: int = Field(description="The process exit code")
    summary: dict[str, Any] = Field(description="Counts behind the outcome line")
    next_actions: list[NextActionModel] = Field(description="Commands worth running next")
    failure: FailureModel | None = Field(description="null exactly when exit_code is 0")


class CommandError(CommandDocument):
    """A command that failed before it produced a result of its own.

    A usage error, a refused prompt or an error the command reports with
    nothing else to say: the envelope and ``error``, and no other key.
    """

    model_config = ConfigDict(extra="forbid")

    ok: Literal[False]
    status: Literal["failed"]
    error: str
    failure: FailureModel


class Counts(ResultModel):
    """Objects by family."""

    rules: int
    threats: int
    objectives: int


class TextEditModel(ResultModel):
    """Replace the text from (line, column) up to (end_line, end_column). 1-based."""

    line: int
    column: int
    end_line: int
    end_column: int = Field(description="Exclusive")
    replacement: str


class FixModel(ResultModel):
    """Edits that resolve a finding. Safe ones may be applied without review."""

    safe: bool
    edits: list[TextEditModel]


class DiagnosticFields(ResultModel):
    """The fields every finding carries (see ``opentide explain``)."""

    code: str = Field(description="Stable snake_case diagnostic code")
    severity: str
    message: str
    path: str | None = Field(None, description="Workspace-relative path")
    line: int | None = Field(None, description="1-based")
    column: int | None = Field(None, description="1-based, Unicode code points")
    end_column: int | None = Field(None, description="Exclusive")
    field_path: list[str] = Field(default_factory=list, description="YAML path")
    help: str | None = None
    fix: FixModel | None = None
    explain: str | None = Field(None, description="The opentide explain command for the code")


class ValidationIssueModel(DiagnosticFields):
    """A validation issue: the engine's fields plus the diagnostic fields."""

    severity: Literal["error", "warning"]
    object_uuid: str
    object_type: str
    file_path: str | None = Field(description="Absolute path")
    yaml_line: int | None = Field(description="0-based")
    suggestion: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ValidationReportModel(ResultModel):
    """A validation session: its issues, its warnings and its statistics."""

    ok: bool
    issues: list[ValidationIssueModel]
    warnings: list[ValidationIssueModel]
    stats: dict[str, Any]
