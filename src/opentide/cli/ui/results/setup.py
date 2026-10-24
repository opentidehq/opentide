"""Results of ``opentide setup`` and its subcommands."""

from __future__ import annotations

from pydantic import Field

from opentide.cli.ui.results.base import CommandDocument, ResultModel


class SetupFiles(ResultModel):
    """Keys the setup steps share: where they wrote, and what."""

    path: str | None = Field(None, description="The repository set up")
    files: list[str] | None = Field(None, description="Files written")
    skipped: list[str] | None = Field(None, description="Files left as they were")
    advice: str | None = None


class RepoFields(SetupFiles):
    platforms: list[str] | None = Field(None, description="Platforms enabled")
    platform_files: list[str] | None = Field(None, description="Platform configurations written")


class CiFields(RepoFields):
    ci: str | None = Field(None, description="The CI provider")
    default_branch: str | None = None


class SetupStep(CiFields):
    """One step of ``opentide setup``: its name, and the result of the subcommand it ran."""

    step: str = Field(description="repo, platforms, ci, vscode, promotion, ...")
    message: str | None = None
    status: str | None = None
    warnings: list[str] | None = None
    updated: list[str] | None = None
    generated: list[str] | None = None
    deprecated: str | None = None
    installed: bool | None = None
    mcp_available: bool | None = None
    skills: list[str] | None = None
    also_applied: list[str] | None = None


class SetupResult(CommandDocument):
    """``opentide setup``: the steps a scripted or interactive setup ran."""

    path: str | None = None
    steps: list[SetupStep] = Field(default_factory=list)
    platforms: list[str] | None = None


class SetupRepoResult(CommandDocument, RepoFields):
    """``opentide setup repo``: a detection repository scaffold."""


class SetupPlatformsResult(CommandDocument, RepoFields):
    """``opentide setup platforms``: platform configuration files."""

    updated: list[str] | None = Field(None, description="Configurations enabled in place")


class SetupCiResult(CommandDocument, CiFields):
    """``opentide setup ci``: CI/CD pipeline files."""


class SetupEnvResult(CommandDocument, SetupFiles):
    """``opentide setup env``: ``.env.example`` and its ignore rule."""


class SetupHooksResult(CommandDocument, SetupFiles):
    """``opentide setup hooks``: validate-on-commit hooks."""

    installed: bool | None = Field(None, description="Whether the Git hook was installed")


class SetupMcpResult(CommandDocument, SetupFiles):
    """``opentide setup mcp``: MCP configuration for editors and agents."""

    mcp_available: bool | None = Field(None, description="Whether the MCP server can start")


class SetupVscodeResult(CommandDocument, SetupFiles):
    """``opentide setup vscode``: VS Code schemas and snippets (deprecated)."""

    generated: list[str] | None = None
    deprecated: str | None = None


class SetupSkillsResult(CommandDocument, SetupFiles):
    """``opentide setup skills``: agent skills installed."""

    skills: list[str] | None = Field(None, description="Skills installed, by slug")
    also_applied: list[str] | None = None


class SkillInfo(ResultModel):
    name: str
    slug: str
    description: str
    installed: bool
    path: str


class SkillsCatalogue(ResultModel):
    source: str | None = Field(None, description="The catalogue, as repository@ref")
    manifest_source: str | None = None
    manifest_refreshed: bool | None = None


class SkillsDiscoverResult(CommandDocument, SkillsCatalogue):
    """``opentide setup skills discover``: skills in the catalogue."""

    skills: list[SkillInfo] = Field(default_factory=list)
    count: int | None = None


class SkillsShowResult(CommandDocument, SkillsCatalogue):
    """``opentide setup skills show``: one skill."""

    skill: SkillInfo | None = None
    install_hint: str | None = None
