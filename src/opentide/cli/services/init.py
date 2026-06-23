"""Repository scaffolding for opentide init."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from opentide.cli.enums import CiPlatform, DetectionPlatform

logger = structlog.get_logger("opentide.cli.services.init")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext
_DEFAULT_STATUSES = (
    "DESIGN",
    "DEVELOPMENT",
    "IMPROVING",
    "STAGING",
    "ACCEPTANCE",
    "PRODUCTION",
    "DISABLED",
    "REMOVED",
)


@dataclass
class InitOptions:
    """Non-interactive init configuration."""

    path: Path = Path(".")
    name: str | None = None
    org: str | None = None
    description: str | None = None
    platforms: list[DetectionPlatform] = field(default_factory=list)
    ci: CiPlatform = CiPlatform.github
    staging: bool = True
    promotion: bool = True
    promotion_target: str = "PRODUCTION"
    frameworks: list[str] = field(default_factory=lambda: ["attack"])
    copilot_instructions: bool = False
    vscode_settings: bool = False
    mcp_config: bool = False
    agent_skills: bool = False
    statuses: list[str] | None = None
    yes: bool = False


def _repo_template_root() -> Path:
    from opentide.core.root import get_repo_root

    return get_repo_root()


def _write_readme(target: Path, options: InitOptions) -> None:
    name = options.name or target.name
    org = options.org or "Security Operations"
    description = options.description or "Detection-as-code repository powered by OpenTide"
    content = f"# {name}\n\n{description}\n\n**Organisation:**{org}\n\n## Quick start\n\n```bash\nopentide validate\nopentide generate\nopentide deploy --platform sentinel --dry-run\n```\n\n## Platforms\n\n{chr(10).join(f'- {p.value}' for p in options.platforms) or '- (configure platforms in Configurations/)'}\n"
    (target / "README.md").write_text(content, encoding="utf-8")


def _write_gitignore(target: Path) -> None:
    (target / ".gitignore").write_text(
        "\n".join(
            [
                "__pycache__/",
                "*.pyc",
                ".venv/",
                "dist/",
                "build/",
                "*.egg-info/",
                ".pytest_cache/",
                "playbook_map.xlsx",
                "Schemas/Indexes/cache/",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _scaffold_directories(target: Path) -> None:
    dirs = [
        "Objects/Threat Vectors",
        "Objects/Detection Objectives",
        "Objects/Detection Rules",
        "Configurations/platforms",
        "Schemas",
        "External",
        ".vscode",
        ".github/workflows",
        ".agents/skills",
    ]
    for rel in dirs:
        (target / rel).mkdir(parents=True, exist_ok=True)


def _write_ci_workflows(target: Path, options: InitOptions) -> None:
    from opentide.ci.models import CiRenderOptions
    from opentide.cli.services.ci_generator import write_ci

    if options.ci is CiPlatform.none:
        return
    write_ci(target, CiRenderOptions.from_init_options(options))


def _copy_ai_assets(target: Path, options: InitOptions) -> None:
    root = _repo_template_root()
    if options.copilot_instructions:
        src = root / ".github" / "copilot-instructions.md"
        if src.is_file():
            shutil.copy2(src, target / ".github" / "copilot-instructions.md")
    if options.agent_skills:
        skills_src = root / ".agents" / "skills"
        skills_dst = target / ".agents" / "skills"
        if skills_src.is_dir():
            for path in skills_src.rglob("*"):
                if path.is_file():
                    rel = path.relative_to(skills_src)
                    out = skills_dst / rel
                    out.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, out)
    if options.vscode_settings:
        settings = {
            "yaml.schemas": {"Schemas/MDR Schema.json": "Objects/Detection Rules/**/*.yaml"}
        }
        (target / ".vscode" / "settings.json").write_text(
            json.dumps(settings, indent=2), encoding="utf-8"
        )
    if options.mcp_config:
        mcp = {"mcpServers": {"opentide": {"command": "opentide-mcp"}}}
        (target / ".vscode" / "mcp.json").write_text(json.dumps(mcp, indent=2), encoding="utf-8")


def run_init(options: InitOptions) -> dict[str, object]:
    """Create a detection repository scaffold."""
    target = options.path.resolve()
    target.mkdir(parents=True, exist_ok=True)
    _scaffold_directories(target)
    _write_gitignore(target)
    _write_readme(target, options)
    _write_ci_workflows(target, options)
    _copy_ai_assets(target, options)
    logger.info("repository_created", detail=str(target))
    return {
        "message": "Repository scaffold created",
        "path": str(target),
        "platforms": [p.value for p in options.platforms],
        "ci": options.ci.value,
        "statuses": options.statuses or list(_DEFAULT_STATUSES),
    }


def run_interactive_init(ctx: CliContext, base_path: Path) -> dict[str, object]:
    """Launch the interactive onboarding wizard."""
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
    options = InitOptions(path=base_path)
    options.name = Prompt.ask("Repository name", default=base_path.name)
    options.org = Prompt.ask("Organisation / team", default="")
    options.description = Prompt.ask("Description", default="Detection-as-code")
    console.print("\n[bold]Step 2 — Detection Platforms[/] (comma-separated keys)")
    console.print(
        "Choices: sentinel, splunk, crowdstrike, defender, sentinel-one, carbon-black, harfanglab"
    )
    platform_input = Prompt.ask("Platforms", default="sentinel,defender")
    for token in platform_input.split(","):
        token = token.strip().replace("-", "_")
        if token == "sentinel_one":
            options.platforms.append(DetectionPlatform.sentinel_one)
        elif token == "carbon_black":
            options.platforms.append(DetectionPlatform.carbon_black)
        elif token == "defender":
            options.platforms.append(DetectionPlatform.defender)
        elif token:
            try:
                options.platforms.append(DetectionPlatform(token))
            except ValueError:
                logger.warning("event", detail=f"Unknown platform skipped: {token}")
    ci_choice = Prompt.ask(
        "CI/CD platform", choices=["github", "gitlab", "azure", "none"], default="github"
    )
    options.ci = CiPlatform(ci_choice)
    options.staging = Confirm.ask("Enable staging deployments on PRs?", default=True)
    options.promotion = Confirm.ask("Enable automatic status promotion?", default=True)
    options.copilot_instructions = Confirm.ask("Generate Copilot instructions?", default=False)
    options.vscode_settings = Confirm.ask("Generate VS Code settings?", default=False)
    options.mcp_config = Confirm.ask("Generate MCP server config?", default=False)
    options.agent_skills = Confirm.ask("Generate agent skills?", default=False)
    ctx.apply_environment()
    return run_init(options)
