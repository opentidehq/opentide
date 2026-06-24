"""Full setup orchestration for ``opentide setup``."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from opentide.cli.enums import CiPlatform, DetectionPlatform, McpHost, SkillTarget
from opentide.cli.services.setup.ci import CiSetupOptions, run_ci_setup
from opentide.cli.services.setup.interactive import (
    MCP_LABELS,
    SKILL_LABELS,
    mcp_hosts_from_keys,
    parse_multi_select,
    parse_platform_tokens,
    skill_targets_from_keys,
)
from opentide.cli.services.setup.mcp import McpSetupOptions, run_mcp_setup
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup
from opentide.cli.services.setup.skills import SkillsSetupOptions, run_skills_setup
from opentide.cli.services.setup.vscode import run_vscode_all

logger = structlog.get_logger("opentide.cli.services.setup.orchestrator")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext


@dataclass
class SetupOptions:
    """Configuration for the default ``opentide setup`` callback."""

    path: Path = Path(".")
    name: str | None = None
    org: str | None = None
    description: str | None = None
    platforms: list[DetectionPlatform] = field(default_factory=list)
    ci: CiPlatform | None = None
    staging: bool = True
    promotion: bool = True
    promotion_target: str = "PRODUCTION"
    python_version: str = "3.12"
    mcp_hosts: list[McpHost] = field(default_factory=list)
    skill_targets: list[SkillTarget] = field(default_factory=list)
    vscode_setup: bool = False
    yes: bool = False
    run_repo: bool = True
    run_ci: bool = False
    run_mcp: bool = False
    run_skills: bool = False


def _repo_options(options: SetupOptions) -> RepoSetupOptions:
    return RepoSetupOptions(
        path=options.path,
        name=options.name,
        org=options.org,
        description=options.description,
        platforms=options.platforms,
        yes=options.yes,
    )


def _ci_options(options: SetupOptions) -> CiSetupOptions:
    assert options.ci is not None
    return CiSetupOptions(
        path=options.path,
        ci=options.ci,
        platforms=options.platforms,
        staging=options.staging,
        promotion=options.promotion,
        promotion_target=options.promotion_target,
        python_version=options.python_version,
        yes=options.yes,
    )


def _skills_options(options: SetupOptions) -> SkillsSetupOptions:
    return SkillsSetupOptions(
        path=options.path,
        targets=options.skill_targets,
        name=options.name,
        org=options.org,
        description=options.description,
        yes=options.yes,
    )


def run_setup(options: SetupOptions) -> dict[str, object]:
    """Run configured setup steps and aggregate results."""
    results: dict[str, object] = {"path": str(options.path.resolve()), "steps": []}
    steps = results["steps"]
    assert isinstance(steps, list)

    if options.run_repo:
        repo_result = run_repo_setup(_repo_options(options))
        steps.append({"step": "repo", **repo_result})

    if options.run_ci and options.ci is not None and options.ci is not CiPlatform.none:
        ci_result = run_ci_setup(_ci_options(options))
        steps.append({"step": "ci", **ci_result})

    if options.run_mcp and options.mcp_hosts:
        mcp_result = run_mcp_setup(
            McpSetupOptions(path=options.path, hosts=options.mcp_hosts, yes=options.yes)
        )
        steps.append({"step": "mcp", **mcp_result})

    if options.run_skills and options.skill_targets:
        skills_result = run_skills_setup(_skills_options(options))
        steps.append({"step": "skills", **skills_result})

    if options.vscode_setup:
        vscode_result = run_vscode_all(options.path.resolve())
        steps.append({"step": "vscode", **vscode_result})

    results["message"] = "Setup complete"
    if options.run_repo and isinstance(steps[0], dict):
        results["platforms"] = steps[0].get("platforms", [])
    return results


def run_interactive_setup(ctx: CliContext, base_path: Path) -> dict[str, object]:
    """Launch the full interactive setup wizard."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt

    console = Console()
    console.print(
        Panel(
            "[bold]OpenTide — Detection Repository Setup[/]",
            title=" OpenTide",
            border_style="blue",
        )
    )
    options = SetupOptions(path=base_path, run_repo=True)
    options.name = Prompt.ask("Repository name", default=base_path.name)
    options.org = Prompt.ask("Organisation / team", default="")
    options.description = Prompt.ask("Description", default="Detection-as-code")
    console.print("\n[bold]Detection Platforms[/] (comma-separated keys)")
    console.print(
        "Choices: sentinel, splunk, crowdstrike, defender, sentinel-one, carbon-black, harfanglab"
    )
    platform_input = Prompt.ask("Platforms", default="sentinel,defender")
    options.platforms = parse_platform_tokens(platform_input)

    ci_choice = Prompt.ask(
        "CI/CD platform", choices=["github", "gitlab", "azure", "none"], default="github"
    )
    options.ci = CiPlatform(ci_choice)
    options.run_ci = options.ci is not CiPlatform.none
    if options.run_ci:
        options.staging = Confirm.ask("Enable staging deployments on PRs?", default=True)
        options.promotion = Confirm.ask("Enable automatic status promotion?", default=True)

    if Confirm.ask("Configure OpenTide MCP?", default=True):
        mcp_raw = Prompt.ask(
            "MCP hosts (comma-separated)",
            default="vscode",
        )
        keys = parse_multi_select(mcp_raw, MCP_LABELS) or ["vscode"]
        options.mcp_hosts = mcp_hosts_from_keys(keys)
        options.run_mcp = True

    if Confirm.ask("Install agent skills?", default=True):
        skills_raw = Prompt.ask(
            "Agent environments (comma-separated)",
            default="generic",
        )
        keys = parse_multi_select(skills_raw, SKILL_LABELS) or ["generic"]
        options.skill_targets = skill_targets_from_keys(keys)
        options.run_skills = True

    if Confirm.ask("Run deprecated VS Code setup (yaml.schemas + snippets)?", default=False):
        options.vscode_setup = True

    ctx.apply_environment()
    return run_setup(options)
