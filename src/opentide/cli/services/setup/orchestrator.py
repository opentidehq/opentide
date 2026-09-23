"""Full setup orchestration for ``opentide setup``."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog
import typer
from rich.markup import escape

from opentide.cli.enums import (
    CiPlatform,
    DetectionPlatform,
    McpHost,
    SkillTarget,
    platform_label,
)
from opentide.cli.services.setup.ci import CiSetupOptions, run_ci_setup
from opentide.cli.services.setup.interactive import (
    MCP_LABELS,
    SKILL_LABELS,
    ask_checkbox,
    ask_confirm,
    ask_platforms,
    ask_select,
    ask_text,
    mcp_hosts_from_keys,
    require_interactive,
    skill_targets_from_keys,
)
from opentide.cli.services.setup.mcp import McpSetupOptions, run_mcp_setup
from opentide.cli.services.setup.platforms import PlatformsSetupOptions, run_platforms_setup
from opentide.cli.services.setup.promotion import effective_promotion, plan_promotion_override
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup
from opentide.cli.services.setup.skills import (
    SkillsDownloadError,
    SkillsSetupOptions,
    run_skills_setup,
    unavailable_skills,
)
from opentide.cli.services.setup.skills_registry import SkillsManifestError
from opentide.cli.services.setup.vscode import run_vscode_setup
from opentide.core.logging.config import get_stdout_console

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
    inflight: bool = True
    #: ``None`` keeps the repository's ``[promotion]`` setting.
    promotion: bool | None = None
    promotion_target: str | None = None
    python_version: str = "3.12"
    explorer_pages: bool = False
    #: ``None`` detects it from the target repository.
    default_branch: str | None = None
    vscode_setup: bool = False
    yes: bool = False
    run_repo: bool = True
    run_ci: bool = False
    run_platforms: bool = False
    run_mcp: bool = False
    mcp_hosts: list[McpHost] = field(default_factory=list)
    run_skills: bool = False
    skill_targets: list[SkillTarget] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


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
        staging=options.staging,
        inflight=options.inflight,
        promotion=options.promotion,
        promotion_target=options.promotion_target,
        python_version=options.python_version,
        explorer_pages=options.explorer_pages,
        default_branch=options.default_branch,
        yes=options.yes,
    )


def run_setup(options: SetupOptions) -> dict[str, object]:
    """Run configured setup steps and aggregate results."""
    steps: list[dict[str, object]] = []
    warnings: list[str] = list(options.warnings)
    results: dict[str, object] = {
        "path": str(options.path.resolve()),
        "steps": steps,
        "warnings": warnings,
    }

    def record(step: str, result: dict[str, object]) -> None:
        # Human output prints only the top-level warnings, never steps[].warnings.
        steps.append({"step": step, **result})
        step_warnings = result.get("warnings")
        if isinstance(step_warnings, list):
            for warning in map(str, step_warnings):
                if warning not in warnings:
                    warnings.append(warning)

    run_platforms = options.run_platforms or (
        bool(options.platforms) and options.run_ci and options.ci is not CiPlatform.none
    )
    if options.run_ci and options.ci is not None and options.ci is not CiPlatform.none:
        # Refuse bad promotion flags before the steps ahead of CI write anything.
        plan_promotion_override(
            options.path.resolve(),
            enabled=options.promotion,
            promotion_target=options.promotion_target,
        )

    if options.run_repo:
        repo_result = run_repo_setup(_repo_options(options))
        record("repo", repo_result)

    if run_platforms and options.platforms:
        plat_result = run_platforms_setup(
            PlatformsSetupOptions(path=options.path, platforms=options.platforms, yes=options.yes)
        )
        record("platforms", plat_result)

    if options.run_ci and options.ci is not None and options.ci is not CiPlatform.none:
        ci_result = run_ci_setup(_ci_options(options))
        record("ci", ci_result)

    if options.run_mcp and options.mcp_hosts:
        mcp_result = run_mcp_setup(
            McpSetupOptions(path=options.path, hosts=options.mcp_hosts, yes=options.yes)
        )
        record("mcp", mcp_result)

    if options.run_skills and options.skill_targets:
        try:
            skills_result = run_skills_setup(
                SkillsSetupOptions(
                    path=options.path,
                    targets=options.skill_targets,
                    name=options.name,
                    org=options.org,
                    description=options.description,
                    yes=options.yes,
                )
            )
            record("skills", skills_result)
        except (typer.BadParameter, SkillsDownloadError, SkillsManifestError) as exc:
            warnings.append(f"Agent skills skipped: {exc}")

    if options.vscode_setup:
        target = options.path.resolve()
        vscode_result = dict(run_vscode_setup(target))
        exit_code = vscode_result.pop("_exit_code", None)
        record("vscode", vscode_result)
        if vscode_result.get("status") == "failed":
            results["status"] = "failed"
            results["message"] = vscode_result.get("message", "VS Code setup failed")
            if exit_code:
                results["_exit_code"] = exit_code

    if results.get("status") != "failed":
        results["message"] = "Setup complete"
    if options.run_repo and steps and isinstance(steps[0], dict):
        results["platforms"] = steps[0].get("platforms", [])
    return results


def _print_setup_plan(options: SetupOptions) -> None:
    """Show the choices and mutation target before files are written."""
    from rich.table import Table
    from rich.text import Text

    table = Table(title="Setup plan", show_header=False)
    table.add_column("Step", style="bold cyan")
    table.add_column("Selection")
    table.add_row("Repository", Text(str(options.path.resolve())))
    table.add_row("Platforms", Text(", ".join(platform_label(item) for item in options.platforms)))
    table.add_row(
        "CI/CD", Text(options.ci.value if options.run_ci and options.ci else "configure later")
    )
    table.add_row(
        "MCP",
        Text(", ".join(item.value for item in options.mcp_hosts) if options.run_mcp else "skip"),
    )
    table.add_row(
        "Agent skills",
        Text(
            ", ".join(item.value for item in options.skill_targets)
            if options.run_skills
            else "skip"
        ),
    )
    get_stdout_console().print(table)


def run_interactive_setup(ctx: CliContext, base_path: Path) -> dict[str, object]:
    """Launch the full interactive setup wizard."""
    from rich.panel import Panel

    require_interactive()
    console = get_stdout_console()
    console.print(
        Panel(
            "[bold]OpenTide — Detection Repository Setup[/]",
            title=" OpenTide",
            border_style="blue",
        )
    )
    options = SetupOptions(path=base_path, run_repo=True)
    options.name = ask_text("Repository name", default=base_path.name)
    options.org = ask_text("Organisation / team (optional)")
    options.description = ask_text("Description (optional)")
    options.platforms = ask_platforms()
    options.run_platforms = True

    options.ci = ask_select(
        "CI/CD platform",
        [
            ("Configure later", CiPlatform.none),
            ("GitHub Actions", CiPlatform.github),
            ("GitLab CI", CiPlatform.gitlab),
            ("Azure Pipelines", CiPlatform.azure),
        ],
        default=CiPlatform.none,
    )
    options.run_ci = options.ci is not CiPlatform.none
    if options.run_ci:
        promoting = effective_promotion(base_path).get("enabled") is True
        features = ask_checkbox(
            "CI workflow features",
            [
                ("Staging deployments on pull requests", "staging"),
                ("Inflight preview shards", "inflight"),
                ("Automatic status promotion", "promotion"),
                ("Explorer pages", "explorer"),
            ],
            defaults=("staging", "inflight", *(("promotion",) if promoting else ())),
        )
        options.staging = "staging" in features
        options.inflight = "inflight" in features
        # Leaving the checkbox where the repository already has it writes nothing.
        chosen = "promotion" in features
        options.promotion = None if chosen is promoting else chosen
        options.explorer_pages = "explorer" in features

    if ask_confirm("Configure OpenTide MCP?", default=False):
        keys = ask_checkbox(
            "MCP hosts",
            [(label, key) for key, label in MCP_LABELS.items()],
            require_selection=True,
        )
        options.mcp_hosts = mcp_hosts_from_keys(keys)
        options.run_mcp = True

    if ask_confirm("Install agent skills?", default=False):
        keys = ask_checkbox(
            "Agent environments",
            [(label, key) for key, label in SKILL_LABELS.items()],
            require_selection=True,
        )
        options.skill_targets = skill_targets_from_keys(keys)
        options.run_skills = True
        preflight = SkillsSetupOptions(path=base_path, targets=options.skill_targets)
        try:
            unavailable = unavailable_skills(preflight)
        except SkillsManifestError as exc:
            options.run_skills = False
            options.warnings.append(f"Agent skills skipped: {exc}")
        else:
            if unavailable:
                options.run_skills = False
                options.warnings.append(
                    "Agent skills unavailable and omitted: " + ", ".join(unavailable)
                )

    _print_setup_plan(options)
    if options.warnings:
        for warning in options.warnings:
            console.print(f"[yellow]WARNING[/] {escape(warning)}")
    if not ask_confirm("Apply this setup plan?", default=True):
        return {
            "message": "Setup cancelled; no files were written",
            "status": "skipped",
            "steps": [],
            "warnings": options.warnings,
        }

    ctx.apply_environment()
    return run_setup(options)
