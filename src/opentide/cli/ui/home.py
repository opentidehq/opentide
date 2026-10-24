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
    status = run("status", "--porcelain")
    changed = len([line for line in (status or "").splitlines() if line.strip()])
    state = "clean" if changed == 0 else f"{changed} changed"
    return f"{branch.strip() or 'no branch'}, {state}"


def _tenants(path: Path) -> int:
    from opentide.core.io import load_toml

    try:
        tenants = load_toml(path).get("tenants")
    except Exception:  # noqa: BLE001 -- a broken file is validate's to report
        return 0
    return len(tenants) if isinstance(tenants, list) else 0


def gather(version: str, start: Path | None = None) -> HomeFacts:
    """Read the facts for the directory *start* (the current one by default)."""
    from opentide.ci.discovery import discover_enabled_platforms, platforms_config_dir
    from opentide.core.root import find_workspace_root, is_workspace_root
    from opentide.registry.discovery import OPENTIDE_DIR

    root = find_workspace_root(start)
    if not is_workspace_root(root):
        return HomeFacts(version=version, workspace=None, git=_git_state(root))
    catalogue = {
        kind: sum(
            1 for suffix in ("*.yaml", "*.yml") for _ in (root / "objects" / kind).rglob(suffix)
        )
        for kind, _ in _KINDS
    }
    schemas = any((root / OPENTIDE_DIR / "schemas").glob("*.schema.json"))
    platforms = {
        name: _tenants(platforms_config_dir(root) / f"{name}.toml")
        for name in discover_enabled_platforms(root)
    }
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


def _home_path(path: Path) -> str:
    try:
        return "~/" + path.resolve().relative_to(Path.home().resolve()).as_posix()
    except (ValueError, RuntimeError, OSError):
        return path.as_posix()


def facts_table(facts: HomeFacts, *, encoding: str = "utf-8") -> Text:
    """``workspace``, ``catalogue``, ``health`` and ``platforms`` as label/value rows."""
    separator = f" {glyph('separator', encoding=encoding)} "
    rows: list[tuple[Text, Text]] = []

    def label(text: str) -> Text:
        return Text(text, style="bold dim")

    if facts.workspace is None:
        rows.append((label("workspace"), Text("none here", style="yellow")))
    else:
        where = Text(_home_path(facts.workspace), style="underline")
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
                    style="dim" if tenants else "yellow",
                )
                rows.append((label("platforms" if number == 0 else ""), value))
        else:
            rows.append((label("platforms"), Text("none enabled", style="yellow")))
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
    rows = columns(
        [(Text(step.command, style="bold"), Text(step.reason, style="dim")) for step in steps],
        gap=3,
        indent=2,
    )
    footer = Text.assemble(
        ("opentide --help", "bold"),
        (" for every command", "dim"),
        (f" {glyph('separator', encoding=encoding)} ", "dim"),
        ("opentide --json <command>", "bold"),
        (" for agents", "dim"),
    )
    return Padding(Group(top, Text(), heading, rows, Text(), footer), (1, 0, 0, 2), expand=False)


def render_home(console: Console, facts: HomeFacts) -> None:
    """Print the home screen."""
    console.print(home_view(console, facts))
