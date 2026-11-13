"""Results of ``opentide setup`` and its subcommands."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from opentide.cli.ui.results.base import CommandDocument, ResultModel

_EXTENSION_MCP = (
    "true when .vscode/extensions.json recommends the opentide VS Code extension "
    "(opentidehq.opentide), which provides the opentide MCP server to VS Code"
)

_CLAUDE_DESKTOP_CONFIG = (
    "With --claude-desktop: the absolute path of the Claude Desktop config written, "
    "which is outside the repository"
)


class PlannedFile(ResultModel):
    """``setup --plan``: one file a step would write, remove, or leave as it is."""

    path: str = Field(
        description=(
            "Relative to the repository set up; absolute for a file outside it "
            "(Claude Desktop's config)"
        )
    )
    action: Literal["create", "merge", "skip", "delete"]


class SetupFiles(ResultModel):
    """Keys the setup steps share: where they wrote, and what."""

    path: str | None = Field(None, description="The repository set up")
    files: list[str | PlannedFile] | None = Field(
        None, description="Files written; with --plan, the files each step would write"
    )
    skipped: list[str] | None = Field(None, description="Files left as they were")
    advice: str | None = None


class RepoFields(SetupFiles):
    platforms: list[str] | None = Field(None, description="Platforms enabled")
    platform_files: list[str] | None = Field(None, description="Platform configurations written")
    # Added by #643 (flow), declared ahead so either merge order stays green.
    name: str | None = Field(None, description="The repository name")
    scaffolded: bool | None = Field(None, description="Whether the scaffold was written")
    gitignore_added: list[str] | None = Field(
        None, description="Lines .gitignore gained: the opentide ones an existing file lacked"
    )


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
    extension_mcp: bool | None = None
    claude_desktop_config: str | None = Field(None, description=_CLAUDE_DESKTOP_CONFIG)
    detail: str | None = None
    skills: list[str] | None = None
    also_applied: list[str] | None = None


class SetupPlanFields(ResultModel):
    """``--plan`` on any setup command: nothing was written; ``steps`` says what would be."""

    plan: bool | None = Field(None, description="True for --plan: nothing was written")
    steps: list[SetupStep] | None = Field(None, description="With --plan, each step's files")


class SetupResult(CommandDocument):
    """``opentide setup``: the steps a scripted or interactive setup ran."""

    path: str | None = None
    steps: list[SetupStep] = Field(default_factory=list)
    platforms: list[str] | None = None
    plan: bool | None = Field(None, description="True for --plan: nothing was written")


class SetupRepoResult(CommandDocument, RepoFields, SetupPlanFields):
    """``opentide setup repo``: a detection repository scaffold."""


class SetupPlatformsResult(CommandDocument, RepoFields, SetupPlanFields):
    """``opentide setup platforms``: platform configuration files."""

    updated: list[str] | None = Field(None, description="Configurations enabled in place")


class SetupCiResult(CommandDocument, CiFields, SetupPlanFields):
    """``opentide setup ci``: CI/CD pipeline files."""


class SetupEnvResult(CommandDocument, SetupFiles, SetupPlanFields):
    """``opentide setup env``: ``.env.example`` and its ignore rule."""


class SetupHooksResult(CommandDocument, SetupFiles, SetupPlanFields):
    """``opentide setup hooks``: validate-on-commit hooks."""

    installed: bool | None = Field(None, description="Whether the Git hook was installed")


class SetupMcpResult(CommandDocument, SetupFiles, SetupPlanFields):
    """``opentide setup mcp``: MCP configuration for editors and agents."""

    mcp_available: bool | None = Field(None, description="Whether the MCP server can start")
    extension_mcp: bool | None = Field(None, description=_EXTENSION_MCP)
    detail: str | None = Field(None, description="What extension_mcp means, in a sentence")
    claude_desktop_config: str | None = Field(None, description=_CLAUDE_DESKTOP_CONFIG)


class SetupVscodeResult(CommandDocument, SetupFiles, SetupPlanFields):
    """``opentide setup vscode``: the extension recommendation and snippets (deprecated)."""

    generated: list[str] | None = None
    deprecated: str | None = None
    extension_mcp: bool | None = Field(None, description="With --mcp: " + _EXTENSION_MCP)
    detail: str | None = Field(None, description="What extension_mcp means, in a sentence")


class SetupSkillsResult(CommandDocument, SetupFiles, SetupPlanFields):
    """``opentide setup skills``: agent skills installed."""

    skills: list[str] | None = Field(None, description="Skills installed, by slug")
    also_applied: list[str] | None = None
    plugin: str | None = Field(
        None, description="The Agent Plugin registered for Claude Code, with --plugin"
    )


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
