"""``opentide validate --watch``: re-validate object files when they change on disk.

:class:`Watcher` polls modification times under the object folders (every
0.5 s), and on a change validates again: only the changed files when their
references did not move, everything when a file was added or removed or a
UUID in it changed, since another object's findings may then change too. It
keeps the findings of every file, so each run reports the whole workspace.

:class:`LiveView` draws the findings and the outcome line in a Rich ``Live``
view (``human`` mode); :class:`PlainView` prints the frames a run found and
one outcome line per run (``plain`` mode). ``json``, ``agent`` and ``mcp``
never watch: the command refuses before it gets here.

The clock, the sleep and the file listing are parameters, so tests drive the
loop without waiting or touching the disk.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console, Group
from rich.live import Live
from rich.text import Text

from opentide.cli.ui.codeframe import diagnostic_lines, render_diagnostics, sort_diagnostics
from opentide.cli.ui.diagnostics import Diagnostic, SourceFiles
from opentide.cli.ui.fixes import plan_fixes
from opentide.cli.ui.glyphs import glyph
from opentide.cli.ui.mode import OutputMode
from opentide.cli.ui.render import OutcomeKind, outcome_text

#: Seconds between two looks at the object folders.
POLL_INTERVAL = 0.5

#: ``path -> (mtime_ns, size)`` of every object file.
Snapshot = dict[Path, tuple[int, int]]

#: Validates the given files, or the command's whole scope for ``None``;
#: returns the findings and how many objects were checked.
Validate = Callable[[Sequence[Path] | None], tuple[Sequence[Diagnostic], int]]

_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def object_files(roots: Iterable[Path]) -> list[Path]:
    """The files the registry reads: ``*.yaml`` under each folder, ``*.debug.yaml`` left out."""
    found: set[Path] = set()
    for root in roots:
        try:
            found.update(
                path
                for path in root.rglob("*.yaml")
                if not path.name.endswith(".debug.yaml") and path.is_file()
            )
        except OSError:
            continue
    return sorted(found)


def take_snapshot(roots: Iterable[Path]) -> Snapshot:
    """Modification time and size of every object file under *roots*."""
    snapshot: Snapshot = {}
    for path in object_files(roots):
        try:
            stat = path.stat()
        except OSError:
            continue
        snapshot[path] = (stat.st_mtime_ns, stat.st_size)
    return snapshot


def references(path: Path) -> frozenset[str]:
    """The UUIDs written in *path*: the object's own and every one it points at."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    return frozenset(match.lower() for match in _UUID.findall(text))


@dataclass(frozen=True)
class Changes:
    """What differs between two snapshots."""

    added: frozenset[Path] = frozenset()
    removed: frozenset[Path] = frozenset()
    modified: frozenset[Path] = frozenset()

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    @classmethod
    def between(
        cls, old: Mapping[Path, tuple[int, int]], new: Mapping[Path, tuple[int, int]]
    ) -> Changes:
        return cls(
            added=frozenset(new.keys() - old.keys()),
            removed=frozenset(old.keys() - new.keys()),
            modified=frozenset(path for path in old.keys() & new.keys() if old[path] != new[path]),
        )


@dataclass(frozen=True)
class WatchRun:
    """One validation pass and the state of the whole workspace after it."""

    number: int
    #: Every finding in the workspace, in frame order.
    diagnostics: tuple[Diagnostic, ...]
    #: The findings this pass produced (all of them on a full pass).
    found: tuple[Diagnostic, ...]
    objects: int
    errors: int
    warnings: int
    files: int
    failed: bool
    seconds: float
    #: Findings ``validate --fix`` would fix.
    fixable: int = 0
    #: ``True`` when only the changed files were validated.
    scoped: bool = False
    changed: tuple[Path, ...] = ()

    @property
    def summary(self) -> dict[str, int]:
        return {
            "objects": self.objects,
            "errors": self.errors,
            "warnings": self.warnings,
            "files": self.files,
            "fixable": self.fixable,
        }


@dataclass
class Watcher:
    """Polls the object folders and re-validates what changed."""

    roots: Sequence[Path]
    validate: Validate
    strict: bool = False
    #: ``False`` when the command was narrowed (``--file``, ``--uuid``, ``--type``):
    #: every pass then validates that scope again.
    scoped_runs: bool = True
    #: Warning codes ``--strict`` does not fail on.
    strict_exempt: frozenset[str] = frozenset()
    snapshot: Callable[[Sequence[Path]], Snapshot] = take_snapshot
    read_references: Callable[[Path], frozenset[str]] = references
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    interval: float = POLL_INTERVAL

    _files: Snapshot = field(default_factory=dict, init=False)
    _references: dict[Path, frozenset[str]] = field(default_factory=dict, init=False)
    _findings: dict[Path | None, list[Diagnostic]] = field(default_factory=dict, init=False)
    _objects: int = field(default=0, init=False)
    _runs: int = field(default=0, init=False)

    def start(self) -> WatchRun:
        """Read the folders and validate the whole scope once."""
        self._files = self.snapshot(self.roots)
        self._references = {path: self.read_references(path) for path in self._files}
        return self._full(())

    def poll(self) -> WatchRun | None:
        """Validate again if a file changed since the last look; ``None`` otherwise."""
        current = self.snapshot(self.roots)
        changes = Changes.between(self._files, current)
        self._files = current
        if not changes:
            return None
        moved = bool(changes.added or changes.removed)
        for path in changes.removed:
            self._references.pop(path, None)
        for path in changes.added | changes.modified:
            refs = self.read_references(path)
            if self._references.get(path) != refs:
                moved = True
            self._references[path] = refs
        changed = tuple(sorted(changes.added | changes.removed | changes.modified))
        if moved or not self.scoped_runs:
            return self._full(changed)
        return self._scoped(changed)

    def run(self, show: Callable[[WatchRun], None]) -> None:
        """Validate, show, then poll forever. Ctrl-C (``KeyboardInterrupt``) ends it."""
        show(self.start())
        while True:
            self.sleep(self.interval)
            found = self.poll()
            if found is not None:
                show(found)

    def _full(self, changed: tuple[Path, ...]) -> WatchRun:
        started = self.clock()
        diagnostics, objects = self.validate(None)
        self._findings = _by_file(diagnostics)
        self._objects = objects
        return self._result(tuple(diagnostics), started, scoped=False, changed=changed)

    def _scoped(self, changed: tuple[Path, ...]) -> WatchRun:
        started = self.clock()
        diagnostics, _objects = self.validate(changed)
        targets = {_key(path) for path in changed}
        if any(_key(item.file_path) not in targets for item in diagnostics):
            # A finding outside the changed files: only a full pass can say
            # what else it changed.
            return self._full(changed)
        for target in targets:
            self._findings.pop(target, None)
        for key, items in _by_file(diagnostics).items():
            self._findings[key] = items
        return self._result(tuple(diagnostics), started, scoped=True, changed=changed)

    def _result(
        self,
        found: tuple[Diagnostic, ...],
        started: float,
        *,
        scoped: bool,
        changed: tuple[Path, ...],
    ) -> WatchRun:
        self._runs += 1
        everything = tuple(
            sort_diagnostics(item for items in self._findings.values() for item in items)
        )
        errors = sum(1 for item in everything if item.severity == "error")
        warnings = sum(1 for item in everything if item.severity == "warning")
        failing_warnings = any(
            item.severity == "warning" and item.code not in self.strict_exempt
            for item in everything
        )
        return WatchRun(
            number=self._runs,
            diagnostics=everything,
            found=tuple(sort_diagnostics(found)),
            objects=self._objects,
            errors=errors,
            warnings=warnings,
            files=len({item.path for item in everything if item.path is not None}),
            failed=bool(errors) or (self.strict and failing_warnings),
            fixable=len(plan_fixes(everything).changes),
            seconds=self.clock() - started,
            scoped=scoped,
            changed=changed,
        )


def _key(path: Path | None) -> Path | None:
    if path is None:
        return None
    try:
        return path.resolve()
    except OSError:  # pragma: no cover - unresolvable path
        return path


def _by_file(diagnostics: Iterable[Diagnostic]) -> dict[Path | None, list[Diagnostic]]:
    grouped: dict[Path | None, list[Diagnostic]] = {}
    for item in diagnostics:
        grouped.setdefault(_key(item.file_path), []).append(item)
    return grouped


# --------------------------------------------------------------------------
# Views
# --------------------------------------------------------------------------


def outcome_kind_of(run: WatchRun) -> OutcomeKind:
    return "failed" if run.failed else "ok"


@dataclass
class PlainView:
    """Per pass: the frames it found, then one outcome line. Nothing is redrawn."""

    console: Console
    describe: Callable[[WatchRun], str]
    mode: OutputMode = OutputMode.PLAIN
    quiet: bool = False
    cwd: Path | None = None

    def __call__(self, run: WatchRun) -> None:
        render_diagnostics(self.console, run.found, mode=self.mode, quiet=self.quiet, cwd=self.cwd)
        encoding = self.console.encoding or "utf-8"
        self.console.print(
            outcome_text(outcome_kind_of(run), self.describe(run), encoding=encoding),
            soft_wrap=True,
        )


@dataclass
class LiveView:
    """Every finding in the workspace and the outcome line, redrawn in place."""

    console: Console
    describe: Callable[[WatchRun], str]
    footer: str = ""
    quiet: bool = False
    cwd: Path | None = None
    _live: Live | None = field(default=None, init=False)

    def __enter__(self) -> LiveView:
        self._live = Live(
            Text(""),
            console=self.console,
            auto_refresh=False,
            transient=False,
            vertical_overflow="crop",
        )
        self._live.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._live is not None:
            self._live.__exit__(None, None, None)
            self._live = None

    def __call__(self, run: WatchRun) -> None:
        group = self.renderable(run)
        if self._live is None:  # pragma: no cover - used outside its context
            self.console.print(group)
            return
        self._live.update(group, refresh=True)

    def renderable(self, run: WatchRun) -> Group:
        """The frames that fit above the outcome line, the outcome line, and the footer."""
        encoding = self.console.encoding or "utf-8"
        sources = SourceFiles()
        frames: list[Text] = []
        shown = [item for item in run.diagnostics if not self.quiet or item.severity == "error"]
        for diagnostic in shown:
            frames.extend(
                diagnostic_lines(diagnostic, sources=sources, encoding=encoding, cwd=self.cwd)
            )
            frames.append(Text(""))
        room = max(self.console.size.height - 3, 1)
        if len(frames) > room:
            hidden = len(frames) - (room - 1)
            frames = [*frames[: room - 1], Text(f"… {hidden} more lines", style="dim")]
        footer = Text(self.footer_text(run), style="dim")
        outcome = outcome_text(outcome_kind_of(run), self.describe(run), encoding=encoding)
        return Group(*frames, outcome, footer)

    def footer_text(self, run: WatchRun) -> str:
        separator = glyph("separator", encoding=self.console.encoding or "utf-8")
        parts = [self.footer] if self.footer else []
        if run.changed:
            what = _display(run.changed[0], self.cwd)
            if len(run.changed) > 1:
                what += f" and {len(run.changed) - 1} more"
            parts.append(f"{'re-checked' if run.scoped else 'changed'}: {what}")
        parts.append(f"run {run.number} at {time.strftime('%H:%M:%S')}")
        parts.append("Ctrl-C to stop")
        return f" {separator} ".join(parts)


def _display(path: Path, cwd: Path | None) -> str:
    base = cwd or Path.cwd()
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()
