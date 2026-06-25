"""Detection repository scaffolding."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.interactive import parse_platform_tokens
from opentide.registry.discovery import OPENTIDE_DIR

logger = structlog.get_logger("opentide.cli.services.setup.repo")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext

SCAFFOLD_DIRS = (
    "objects/threats",
    "objects/objectives",
    "objects/rules",
    f"{OPENTIDE_DIR}/configurations/platforms",
    f"{OPENTIDE_DIR}/schemas",
    f"{OPENTIDE_DIR}/templates",
    f"{OPENTIDE_DIR}/exports",
    f"{OPENTIDE_DIR}/inflight",
    "docs/rules",
    "docs/threats",
    "docs/objectives",
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
        or f"- (configure platforms in {OPENTIDE_DIR}/configurations/)"
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
                f"{OPENTIDE_DIR}/exports/*.export.json",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def run_repo_setup(options: RepoSetupOptions) -> dict[str, object]:
    """Create detection repository directory layout."""
    target = options.path.resolve()
    target.mkdir(parents=True, exist_ok=True)
    for rel in SCAFFOLD_DIRS:
        (target / rel).mkdir(parents=True, exist_ok=True)
    _write_readme(target, options)
    _write_gitignore(target)
    platforms = [p.value for p in options.platforms]
    logger.info("repo_scaffold_created", path=str(target), platforms=platforms)
    return {
        "message": "Repository scaffold created",
        "path": str(target),
        "platforms": platforms,
    }


def run_interactive_repo_setup(ctx: CliContext, base_path: Path) -> dict[str, object]:
    """Prompt for repository metadata and scaffold the workspace."""
    from rich.prompt import Prompt

    ctx.apply_environment()
    target = base_path.resolve()
    name = Prompt.ask("Repository name", default=target.name)
    org = Prompt.ask("Organisation / team", default="Security Operations")
    description = Prompt.ask(
        "Description", default="Detection-as-code repository powered by OpenTide"
    )
    platform_input = Prompt.ask("Platforms (comma-separated)", default="sentinel,defender")
    options = RepoSetupOptions(
        path=target,
        name=name,
        org=org,
        description=description,
        platforms=parse_platform_tokens(platform_input),
        yes=True,
    )
    return run_repo_setup(options)
