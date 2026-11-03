"""Write ``.env.example`` so local and CI environments can set ``OPENTIDE_REPO_ROOT``."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import structlog

logger = structlog.get_logger("opentide.cli.services.setup.env")

ENV_EXAMPLE_PATH = ".env.example"
GITIGNORE_PATH = ".gitignore"
ENV_IGNORE_LINE = ".env"

ENV_EXAMPLE_CONTENT = """\
# opentide environment template. Copy to .env and adjust as needed.
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


def _ignore_key(line: str) -> str:
    """A ``.gitignore`` pattern as compared: ``/opentide-reports/`` is ``opentide-reports``."""
    return line.strip().lstrip("\ufeff").removeprefix("/").rstrip("/")


def append_gitignore_lines(target: Path, lines: Sequence[str]) -> list[str]:
    """Add each of *lines* that ``target/.gitignore`` lacks; return the ones added.

    The file is created when missing. An existing one keeps its content, its
    byte-order mark and its line endings (``\\r\\n`` when it uses them): only the
    missing lines are appended, so a rerun adds nothing. A line counts as
    present when the file has it with or without a leading or trailing ``/``;
    a negated pattern (``!x``) does not count. Raises ``UnicodeDecodeError``
    when the file is not UTF-8.
    """
    dest = target / GITIGNORE_PATH
    if not dest.is_file():
        dest.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
        return list(lines)
    existing = dest.read_bytes().decode("utf-8")
    present = {_ignore_key(line) for line in existing.splitlines()}
    missing = [line for line in lines if _ignore_key(line) not in present]
    if not missing:
        return []
    newline = "\r\n" if "\r\n" in existing else "\n"
    lead = "" if not existing or existing.endswith(("\n", "\r")) else newline
    with dest.open("w", encoding="utf-8", newline="") as handle:
        handle.write(existing + lead + "".join(f"{line}{newline}" for line in missing))
    return missing


def _ensure_gitignore_env(target: Path) -> tuple[str, bool]:
    """Ignore ``.env`` (not ``.env.example``) so secrets stay uncommitted."""
    return GITIGNORE_PATH, bool(append_gitignore_lines(target, [ENV_IGNORE_LINE]))


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
