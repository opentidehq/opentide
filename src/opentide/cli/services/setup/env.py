"""Write ``.env.example`` so local and CI environments can set ``OPENTIDE_REPO_ROOT``."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import structlog

logger = structlog.get_logger("opentide.cli.services.setup.env")

ENV_EXAMPLE_PATH = ".env.example"
GITIGNORE_PATH = ".gitignore"
ENV_IGNORE_LINE = ".env"

ENV_EXAMPLE_CONTENT = """\
# OpenTide environment template. Copy to .env and adjust as needed.
# The CLI, MCP server, and SDK honour OPENTIDE_REPO_ROOT (same as --repo).
OPENTIDE_REPO_ROOT=.
"""


@dataclass
class EnvSetupOptions:
    """Non-interactive environment-file setup."""

    path: Path = Path(".")
    yes: bool = False


def _ensure_env_example(target: Path) -> tuple[str, bool]:
    """Create or append ``OPENTIDE_REPO_ROOT`` in ``.env.example``.

    Returns the relative path and whether the file was written or updated.
    """
    dest = target / ENV_EXAMPLE_PATH
    if dest.is_file():
        existing = dest.read_text(encoding="utf-8")
        if "OPENTIDE_REPO_ROOT" in existing:
            return ENV_EXAMPLE_PATH, False
        suffix = "" if existing.endswith("\n") else "\n"
        dest.write_text(existing + suffix + "OPENTIDE_REPO_ROOT=.\n", encoding="utf-8")
        return ENV_EXAMPLE_PATH, True
    dest.write_text(ENV_EXAMPLE_CONTENT, encoding="utf-8")
    return ENV_EXAMPLE_PATH, True


def _gitignore_ignores_env(text: str) -> bool:
    return any(line.strip() == ENV_IGNORE_LINE for line in text.splitlines())


def _ensure_gitignore_env(target: Path) -> tuple[str, bool]:
    """Ignore ``.env`` (not ``.env.example``) so secrets stay uncommitted."""
    dest = target / GITIGNORE_PATH
    if dest.is_file():
        existing = dest.read_text(encoding="utf-8")
        if _gitignore_ignores_env(existing):
            return GITIGNORE_PATH, False
        suffix = "" if existing.endswith("\n") else "\n"
        dest.write_text(existing + suffix + f"{ENV_IGNORE_LINE}\n", encoding="utf-8")
        return GITIGNORE_PATH, True
    dest.write_text(f"{ENV_IGNORE_LINE}\n", encoding="utf-8")
    return GITIGNORE_PATH, True


def run_env_setup(options: EnvSetupOptions) -> dict[str, object]:
    """Write ``.env.example`` with ``OPENTIDE_REPO_ROOT`` and ignore ``.env``."""
    target = options.path.resolve()
    target.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    skipped: list[str] = []
    for relative, changed in (_ensure_env_example(target), _ensure_gitignore_env(target)):
        if changed:
            written.append(relative)
        else:
            skipped.append(relative)
    logger.debug(
        "env_example_setup",
        path=str(target),
        written=written,
        skipped=skipped,
    )
    message = (
        "Environment example written"
        if ENV_EXAMPLE_PATH in written
        else "Environment example already present"
    )
    return {
        "message": message,
        "path": str(target),
        "files": written,
        "skipped": skipped,
    }
