"""The ``opentide setup`` wizard as a person sees it: welcome, summary, outcome, next steps.

The welcome is the one place the full pill logo appears (``human`` mode, a
terminal at least :data:`~opentide.cli.ui.brand.LOGO_MIN_WIDTH` wide, an
encoding with the block characters; otherwise the one-line pill, or no mark).
After the run, :func:`render_summary` lists what was written, before the
warnings and the outcome line; :func:`setup_outcome` builds that line and the
numbered next steps.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.padding import Padding
from rich.text import Text

from opentide.cli.ui import brand
from opentide.cli.ui.contract import NextAction
from opentide.cli.ui.layout import columns
from opentide.cli.ui.mode import OutputMode, get_mode
from opentide.cli.ui.paths import display_path

WELCOME_LINE = "A few questions, then a detection repository with CI, schemas and editor support."

#: What a written path is for, by prefix, in the summary.
_PURPOSES: tuple[tuple[str, str], ...] = (
    ("objects/", "your detection catalogue"),
    (".opentide/configurations/platforms/", "platform configuration"),
    (".github/workflows/", "GitHub Actions pipeline"),
    (".gitlab-ci.yml", "GitLab CI pipeline"),
    ("azure-pipelines", "Azure Pipelines pipeline"),
    (".pre-commit-config.yaml", "validate on commit"),
    (".git/hooks/", "validate on commit"),
    (".vscode/mcp.json", "MCP server for VS Code"),
    (".cursor/", "Cursor configuration"),
    (".mcp.json", "MCP server for Claude Code"),
    (".vscode/", "editor settings"),
    ("README.md", "quick start"),
    (".gitignore", "files git leaves out"),
    (".env.example", "environment template"),
)


def welcome(console: Console, *, version: str, mode: OutputMode | None = None) -> None:
    """The wizard's first screen: the logo, the tagline, and what happens next."""
    mode = mode or get_mode()
    mono = brand.is_mono(console)
    separator = " · "
    if brand.can_draw(console, mode=mode):
        console.print()
        if console.width >= brand.LOGO_MIN_WIDTH:
            console.print(Padding(brand.logo(mono=mono), (0, 0, 0, 2)))
            console.print(
                Text.assemble(("  " + brand.TAGLINE, "italic"), (separator + version, "dim"))
            )
        else:
            console.print(
                Text.assemble(
                    "  ",
                    brand.pill(mono=mono, encoding=console.encoding or "utf-8"),
                    (separator + version, "dim"),
                )
            )
            console.print(Text("  " + brand.TAGLINE, style="italic"))
    else:
        console.print(Text.assemble(("opentide setup", "bold"), (separator + brand.TAGLINE, "")))
    console.print()
    console.print(Text("  " + WELCOME_LINE, style="dim"))
    console.print()


def _steps(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    steps = result.get("steps")
    if isinstance(steps, list):
        return [step for step in steps if isinstance(step, Mapping)]
    return [result]


def written_files(result: Mapping[str, Any]) -> list[str]:
    """Every file the result says it wrote, relative to its repository, in order, once."""
    seen: dict[str, None] = {}
    for step in _steps(result):
        for key in ("files", "platform_files"):
            items = step.get(key)
            if isinstance(items, list):
                for item in items:
                    if item:
                        seen.setdefault(Path(str(item)).as_posix(), None)
    return list(seen)


def _purpose(path: str) -> str:
    for prefix, purpose in _PURPOSES:
        if path.startswith(prefix) or path == prefix.rstrip("/"):
            return purpose
    return ""


def _scaffolded(result: Mapping[str, Any]) -> bool:
    return any(step.get("scaffolded") for step in _steps(result))


def summary_rows(result: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(path, purpose)`` rows for the summary: the catalogue folders, then each file."""
    rows: list[tuple[str, str]] = []
    if _scaffolded(result):
        rows.append(("objects/{threats,objectives,rules}/", "your detection catalogue"))
    rows.extend((path, _purpose(path)) for path in written_files(result))
    return rows


def render_summary(console: Console, result: Mapping[str, Any]) -> None:
    """What the run wrote, one row per path. Nothing when it wrote nothing."""
    rows = summary_rows(result)
    if not rows:
        return
    table = columns(
        [(Text(path, style="bold"), Text(purpose, style="dim")) for path, purpose in rows],
        gap=3,
        indent=2,
    )
    console.print(table, soft_wrap=True)
    console.print()


def _target(result: Mapping[str, Any]) -> Path | None:
    path = result.get("path")
    return Path(str(path)) if path else None


def setup_outcome(
    result: Mapping[str, Any], *, name: str | None = None
) -> tuple[str | None, list[NextAction]]:
    """The outcome line and next steps for a finished setup, or ``(None, [])`` to keep its own.

    ``Created Tutorial Detections in ./tutorial-detections`` when a
    repository was scaffolded, ``Wrote .github/workflows/opentide.yml`` (or
    ``Wrote 3 files``) otherwise.
    """
    if result.get("status") in ("failed", "skipped"):
        return None, []
    target = _target(result)
    files = written_files(result)
    shown = display_path(target) if target is not None else "."
    if _scaffolded(result):
        repo_step = next(step for step in _steps(result) if step.get("scaffolded"))
        title = (
            name
            or str(repo_step.get("name") or "")
            or (target.name if target is not None else "the repository")
        )
        message = f"Created {title} in {shown if shown.startswith(('.', '/')) else './' + shown}"
        actions: list[NextAction] = []
        if target is not None and target.resolve() != Path.cwd().resolve():
            actions.append(NextAction(f"cd {display_path(target).rstrip('/')}"))
        actions.append(NextAction("opentide generate", "schemas, templates and editor snippets"))
        actions.append(NextAction("opentide validate", "check every object before you commit"))
        return message.rstrip("/"), actions[:3]
    if not files:
        return None, []
    if len(files) == 1:
        return f"Wrote {files[0]}", []
    return f"Wrote {len(files)} files", []


def warnings_once(warnings: Iterable[str]) -> list[str]:
    """The warnings in order, each once."""
    return list(dict.fromkeys(str(item) for item in warnings))
