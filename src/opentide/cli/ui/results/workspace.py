"""Results of ``opentide new`` and ``opentide doctor`` (#642)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from opentide.cli.ui.results.base import CommandDocument, ResultModel

# --------------------------------------------------------------------------
# new
# --------------------------------------------------------------------------


class NewOrganisation(ResultModel):
    """The organisation written into the new object's metadata."""

    uuid: str
    name: str


class NewResult(CommandDocument):
    """``opentide new threat|objective|rule``: the file it wrote."""

    path: str = Field(description="The new file, relative to the workspace")
    file_path: str = Field(description="The new file, absolute")
    uuid: str = Field(description="metadata.uuid of the new object")
    type: Literal["threat", "objective", "rule"]
    schema_: str = Field(alias="schema", description="metadata.schema of the new object")
    name: str
    author: str | None = Field(description="metadata.author, from git user.name; null when unset")
    organisation: NewOrganisation | None = Field(
        description="The organisation most catalogue objects carry; null when none does"
    )
    platforms: list[str] = Field(description="Platform blocks written into a rule")
    placeholders: list[str] = Field(
        description="Keys holding a placeholder value marked '# opentide:placeholder'"
    )
    detail: str | None = Field(None, description="The placeholder values to replace")
    generated: list[str] | None = Field(
        None, description="Generation phases run first, because the workspace had no template"
    )


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------


class DoctorCheck(ResultModel):
    """One line of the doctor checklist."""

    code: str = Field(description="Stable name of the check")
    status: Literal["pass", "warn", "fail", "skip"]
    message: str
    fix: str | None = Field(description="The command or step that fixes it")
    subject: str | None = Field(description="What a repeated check is about: a platform, a tenant")


class DoctorResult(CommandDocument):
    """``opentide doctor``: each check and its status."""

    checks: list[DoctorCheck]
