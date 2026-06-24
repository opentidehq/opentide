"""Detection repository scaffolding."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.interactive import parse_platform_tokens

logger = structlog.get_logger("opentide.cli.services.setup.repo")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext

SCAFFOLD_DIRS = (
    "Objects/Threat Vectors",
    "Objects/Detection Objectives",
    "Objects/Detection Rules",
    "Configurations/platforms",
    "Analytics",
    "Schemas",
    "Schemas/Templates",
    "Schemas/Indexes",
    "Schemas/Exports",
    "Schemas/Configurations",
    ".github/workflows",
)


@dataclass
class RepoSetupOptions:
    """Non-interactive repository setup configuration."""

    path: Path = Path(".")
    name: str | None = None
    org: str | None = None
    description: str | None = None
    platforms: list[DetectionPlatform] = field(default_factory=list)
    yes: bool = False


def _write_readme(target: Path, options: RepoSetupOptions) -> None:
    name = options.name or target.name
    org = options.org or "Security Operations"
    description = options.description or "Detection-as-code repository powered by OpenTide"
    platforms = (
        chr(10).join(f"- {p.value}" for p in options.platforms)
        or "- (configure platforms in Configurations/)"
    )
    content = (
        f"# {name}\n\n{description}\n\n**Organisation:** {org}\n\n"
        "## Quick start\n\n```bash\nopentide setup\nopentide validate\n"
        "opentide generate\nopentide deploy --platform sentinel --dry-run\n```\n\n"
        f"## Platforms\n\n{platforms}\n"
    )
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
    for rel in SCAFFOLD_DIRS:
        (target / rel).mkdir(parents=True, exist_ok=True)


def run_repo_setup(options: RepoSetupOptions) -> dict[str, object]:
    """Create a detection repository scaffold."""
    target = options.path.resolve()
    target.mkdir(parents=True, exist_ok=True)
    _scaffold_directories(target)
    _write_gitignore(target)
    _write_readme(target, options)
    logger.info("repository_created", detail=str(target))
    return {
        "message": "Repository scaffold created",
        "path": str(target),
        "platforms": [p.value for p in options.platforms],
    }


def run_interactive_repo_setup(ctx: CliContext, base_path: Path) -> dict[str, object]:
    """Launch the interactive repository setup wizard."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt

    console = Console()
    console.print(
        Panel(
            "[bold]OpenTide — Repository Setup[/]",
            title=" OpenTide",
            border_style="blue",
        )
    )
    options = RepoSetupOptions(path=base_path)
    options.name = Prompt.ask("Repository name", default=base_path.name)
    options.org = Prompt.ask("Organisation / team", default="")
    options.description = Prompt.ask("Description", default="Detection-as-code")
    console.print("\n[bold]Detection Platforms[/] (comma-separated keys)")
    console.print(
        "Choices: sentinel, splunk, crowdstrike, defender, sentinel-one, carbon-black, harfanglab"
    )
    platform_input = Prompt.ask("Platforms", default="sentinel,defender")
    options.platforms = parse_platform_tokens(platform_input)
    ctx.apply_environment()
    return run_repo_setup(options)
