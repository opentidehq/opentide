"""The home screen: what a bare ``opentide`` shows a person at a terminal.

::

    ████████   ▐ ≋ opentide ▌  0.18.0
    ██ icon █  Spec-driven development for agentic detection engineering
    ████████
                workspace  ~/detections  git: main, clean
                catalogue  1 rule · 1 threat · 1 objective
                   health  schemas generated
                platforms  sentinel (no tenant yet)

     ≋  Suggested next
      opentide validate            check every object before you commit
      ...

Only in ``human`` mode; every other mode gets the help, as before. The facts
are read from the files on disk (no registry load, no network), so the screen
costs about what ``--help`` does. Everything here is presentation;
:func:`gather` collects, :func:`home_view` draws.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from opentide.cli.ui import brand
from opentide.cli.ui.contract import NextAction
from opentide.cli.ui.glyphs import glyph
from opentide.cli.ui.layout import columns
from opentide.cli.ui.progress import plural

#: Narrower than this, the icon gives way to the one-line pill.
ICON_MIN_WIDTH = 76

_KINDS = (("rules", "rule"), ("threats", "threat"), ("objectives", "objective"))


@dataclass
class HomeFacts:
    """What the home screen says about the current directory."""

    version: str
    workspace: Path | None
    #: ``main, clean`` / ``main, 3 changed``; ``None`` outside git.
    git: str | None = None
    #: Object files per kind: ``rules``, ``threats``, ``objectives``.
    catalogue: dict[str, int] = field(default_factory=dict)
    schemas: bool = False
    #: Enabled platform → number of ``[[tenants]]``.
    platforms: dict[str, int] = field(default_factory=dict)


def _git_state(path: Path) -> str | None:
    def run(*args: str) -> str | None:
        try:
            done = subprocess.run(
                ["git", *args],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout if done.returncode == 0 else None

    branch = run("rev-parse", "--abbrev-ref", "HEAD")
    if branch is None:
        return None
    name = branch.strip() or "no branch"
    status = run("status", "--porcelain")
    if status is None:
        # git did not answer (timeout, error): say nothing about the tree.
        return name
    changed = len([line for line in status.splitlines() if line.strip()])
    state = "clean" if changed == 0 else f"{changed} changed"
    return f"{name}, {state}"


def _platforms(directory: Path) -> dict[str, int]:
    """Enabled platform → ``[[tenants]]`` count, read straight from the TOML files.

    Read here rather than through ``opentide.ci.discovery``: importing that
    package loads the validation engine and the registry, and the home screen
    has to cost what ``--help`` does.
    """
    from opentide.core.io import load_toml

    platforms: dict[str, int] = {}
    for path in sorted(directory.glob("*.toml")) if directory.is_dir() else ():
        try:
            document = load_toml(path)
        except Exception:
            continue
        platform = document.get("platform")
        if not isinstance(platform, dict) or platform.get("enabled") is not True:
            continue
        tenants = document.get("tenants")
        platforms[path.stem] = len(tenants) if isinstance(tenants, list) else 0
    return platforms


def gather(version: str, start: Path | None = None) -> HomeFacts:
    """Read the facts for the directory *start* (the current one by default)."""
    from opentide.core.root import (
        OPENTIDE_DIR,
        find_workspace_root,
        get_repo_root,
        is_workspace_root,
    )

    # OPENTIDE_REPO_ROOT names the workspace for every command; honour it here too.
    root = find_workspace_root(start) if start is not None else get_repo_root()
    if not is_workspace_root(root):
        return HomeFacts(version=version, workspace=None, git=_git_state(root))
    catalogue = {
        kind: sum(
            1 for suffix in ("*.yaml", "*.yml") for _ in (root / "objects" / kind).rglob(suffix)
        )
        for kind, _ in _KINDS
    }
    schemas = any((root / OPENTIDE_DIR / "schemas").glob("*.schema.json"))
    platforms = _platforms(root / OPENTIDE_DIR / "configurations" / "platforms")
    return HomeFacts(
        version=version,
        workspace=root,
        git=_git_state(root),
        catalogue=catalogue,
        schemas=schemas,
        platforms=platforms,
    )


def next_steps(facts: HomeFacts) -> list[NextAction]:
    """Up to three commands worth running here, most useful first."""
    if facts.workspace is None:
        return [NextAction("opentide setup", "create a detection repository here")]
    steps: list[NextAction] = []
    if not facts.schemas:
        steps.append(NextAction("opentide generate", "schemas, templates and editor snippets"))
    steps.append(NextAction("opentide validate", "check every object before you commit"))
    if not facts.platforms:
        steps.append(NextAction("opentide setup platforms --sentinel", "enable a platform"))
    elif any(count == 0 for count in facts.platforms.values()):
        steps.append(
            NextAction(
                "opentide deploy --strategy PREVIEW --all --dry-run",
                "see what a deploy would do",
            )
        )
    else:
        steps.append(NextAction("opentide info", "the catalogue and its coverage"))
    return steps[:3]


def workspace_path(path: Path, cwd: Path | None = None) -> str:
    """*path* as the reader types it from here: ``.``, ``../..`` or ``detections``.

    Relative to the current directory when the workspace contains it or sits
    inside it; otherwise ``~/…`` or the whole absolute path, never cut.
    """
    import os

    here = (cwd or Path.cwd()).resolve()
    try:
        target = path.resolve()
    except (OSError, RuntimeError):
        return path.as_posix()
    if target == here or here.is_relative_to(target) or target.is_relative_to(here):
        return Path(os.path.relpath(target, here)).as_posix()
    try:
        return "~/" + target.relative_to(Path.home().resolve()).as_posix()
    except (ValueError, RuntimeError, OSError):
        return target.as_posix()


def facts_table(facts: HomeFacts, *, encoding: str = "utf-8") -> Text:
    """``workspace``, ``catalogue``, ``health`` and ``platforms`` as label/value rows."""
    separator = f" {glyph('separator', encoding=encoding)} "
    rows: list[tuple[Text, Text]] = []

    def label(text: str) -> Text:
        return Text(text, style="bold dim")

    if facts.workspace is None:
        rows.append((label("workspace"), Text("none here", style="dim")))
    else:
        where = Text(workspace_path(facts.workspace), style="underline")
        if facts.git:
            where.append(f"  git: {facts.git}", style="dim")
        rows.append((label("workspace"), where))
        counts = separator.join(plural(facts.catalogue.get(kind, 0), noun) for kind, noun in _KINDS)
        rows.append((label("catalogue"), Text(counts)))
        ok = glyph("ok", encoding=encoding)
        health = (
            Text.assemble((ok + " ", "green"), "schemas generated")
            if facts.schemas
            else Text.assemble(("! ", "yellow"), "schemas not generated yet")
        )
        rows.append((label("health"), health))
        if facts.platforms:
            for number, (name, tenants) in enumerate(sorted(facts.platforms.items())):
                value = Text(name, style="bold")
                value.append(
                    f" ({plural(tenants, 'tenant')})" if tenants else " (no tenant yet)",
                    style="dim",
                )
                rows.append((label("platforms" if number == 0 else ""), value))
        else:
            rows.append((label("platforms"), Text("none enabled", style="dim")))
    table = columns(rows, right=(0,))
    table.no_wrap = True
    table.overflow = "ellipsis"
    return table


def home_view(console: Console, facts: HomeFacts) -> RenderableType:
    """The whole screen for *console*: mark, tagline, facts, next steps, help pointer."""
    encoding = console.encoding or "utf-8"
    mono = brand.is_mono(console)
    marks = brand.can_draw(console)
    title = Text.assemble(
        brand.pill(mono=mono, encoding=encoding) if marks else Text("opentide", style="bold"),
        ("  " + facts.version, "dim"),
    )
    right = Group(
        title,
        Text(brand.TAGLINE, style="italic"),
        Text(),
        facts_table(facts, encoding=encoding),
    )
    if marks and console.width >= ICON_MIN_WIDTH:
        lockup = Table.grid(padding=(0, 3))
        lockup.add_column(no_wrap=True)
        lockup.add_column()
        lockup.add_row(brand.icon(mono=mono), Group(Text(), right))
        top: RenderableType = lockup
    else:
        top = right
    steps = next_steps(facts)
    heading = (
        brand.header("Suggested next", mono=mono, encoding=encoding)
        if marks
        else Text("Suggested next", style="bold")
    )
    # The screen is indented by 2: a line wider than what is left would wrap
    # mid-phrase, so a narrow terminal drops the descriptions instead.
    room = console.width - 2
    described = [
        (Text(step.command, style="bold"), Text(step.reason, style="dim")) for step in steps
    ]
    rows = columns(described, gap=3, indent=2)
    if any(line.cell_len > room for line in rows.split("\n")):
        rows = columns([(command,) for command, _ in described], indent=2)
    help_hint = Text.assemble(("opentide --help", "bold"), (" for every command", "dim"))
    json_hint = Text.assemble(("opentide --json <command>", "bold"), (" for agents", "dim"))
    separator = Text(f" {glyph('separator', encoding=encoding)} ", style="dim")
    footer = Text.assemble(help_hint, separator, json_hint)
    if footer.cell_len > room:
        footer = Text.assemble(help_hint, "\n", json_hint)
    return Padding(Group(top, Text(), heading, rows, Text(), footer), (1, 0, 0, 2), expand=False)


def render_home(console: Console, facts: HomeFacts) -> None:
    """Print the home screen."""
    console.print(home_view(console, facts))
