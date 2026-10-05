"""Detection repository scaffolding."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from rich.markup import escape

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.interactive import (
    ask_confirm,
    ask_platforms,
    ask_text,
    require_interactive,
)
from opentide.cli.services.setup.platforms import PlatformsSetupOptions, run_platforms_setup
from opentide.core.logging.config import get_stdout_console
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


def _deploy_commands(options: RepoSetupOptions) -> str:
    if not options.platforms:
        return "opentide deploy --dry-run"
    return "\n".join(
        f"opentide deploy --platform {platform.value} --dry-run" for platform in options.platforms
    )


def _write_readme(target: Path, options: RepoSetupOptions) -> None:
    name = options.name or target.name
    platforms = (
        chr(10).join(f"- {p.value}" for p in options.platforms)
        or f"- (configure platforms in {OPENTIDE_DIR}/configurations/)"
    )
    metadata = ""
    if options.description:
        metadata += f"\n{options.description}\n"
    if options.org:
        metadata += f"\n**Organisation:** {options.org}\n"
    content = (
        f"# {name}\n{metadata}\n"
        "## Quick start\n\n```bash\nopentide setup\nopentide validate\n"
        f"opentide generate\n{_deploy_commands(options)}\n```\n\n"
        f"## Platforms\n\n{platforms}\n"
    )
    (target / "README.md").write_text(content, encoding="utf-8")


def _ignored_readme_flags(options: RepoSetupOptions) -> list[str]:
    ignored: list[str] = []
    if options.name:
        ignored.append("--name")
    if options.org:
        ignored.append("--org")
    if options.description:
        ignored.append("--description")
    return ignored


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
                f"{OPENTIDE_DIR}/states/",
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
        directory = target / rel
        directory.mkdir(parents=True, exist_ok=True)
        if not any(directory.iterdir()):
            (directory / ".gitkeep").write_text("", encoding="utf-8")
    skipped: list[str] = []
    warnings: list[str] = []
    readme = target / "README.md"
    if readme.is_file():
        skipped.append("README.md")
        ignored = _ignored_readme_flags(options)
        if ignored:
            warnings.append(
                "Left README.md unchanged; ignored "
                + ", ".join(ignored)
                + " because the file already exists"
            )
    else:
        _write_readme(target, options)
    gitignore = target / ".gitignore"
    if gitignore.is_file():
        skipped.append(".gitignore")
    else:
        _write_gitignore(target)
    platforms = [p.value for p in options.platforms]
    result: dict[str, object] = {
        "message": "Repository scaffold created",
        "path": str(target),
        "platforms": platforms,
    }
    if skipped:
        result["skipped"] = skipped
    if warnings:
        result["warnings"] = warnings
    if options.platforms:
        plat = run_platforms_setup(
            PlatformsSetupOptions(path=target, platforms=options.platforms, yes=options.yes)
        )
        result["platform_files"] = plat.get("files", [])
    logger.debug("repo_scaffold_created", path=str(target), platforms=platforms)
    return result


def run_interactive_repo_setup(ctx: CliContext, base_path: Path) -> dict[str, object]:
    """Prompt for repository metadata and scaffold the workspace."""
    require_interactive()
    ctx.apply_environment()
    target = base_path.resolve()
    name = ask_text("Repository name", default=target.name)
    org = ask_text("Organisation / team (optional)")
    description = ask_text("Description (optional)")
    options = RepoSetupOptions(
        path=target,
        name=name,
        org=org,
        description=description,
        platforms=ask_platforms(),
        yes=True,
    )
    get_stdout_console().print(f"[bold]Target:[/] {escape(str(target))}")
    if not ask_confirm("Create this repository scaffold?", default=True):
        return {"message": "Repository setup cancelled", "status": "skipped"}
    return run_repo_setup(options)
