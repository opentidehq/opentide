"""Steps of a long run, owned by the CLI: a live checklist for people, one line per step otherwise.

A command opens a :class:`Checklist` and runs each unit of work in a
:meth:`Checklist.step`. The step records what it produced (a count, a unit,
where it went) and how long it took:

``human``
    A Rich ``Live`` checklist on stderr: finished steps as ``✓`` rows, the
    running step with a spinner and the engine stage it is in. When the run
    ends the spinner row is gone and the finished rows stay.
``plain`` and ``agent``
    One line per finished step on stderr, no animation:
    ``✓ schemas · 7 files · 1.6s · .opentide/schemas/``.
``json`` and ``mcp``, and ``--quiet``
    Nothing. The command's result carries the steps instead.

In ``human`` mode the checklist also sets the terminal's tab or taskbar
progress (OSC 9;4) from :attr:`Checklist.completed` and :attr:`Checklist.total`,
where the terminal reads it (:mod:`opentide.cli.ui.terminal_progress`).

Engine modules never print: they call :func:`opentide.core.progress.report_stage`,
which a checklist shows beside the running step. The outcome line is not the
checklist's job; the command prints it from its result.
"""

from __future__ import annotations

import time
from collections.abc import Generator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from types import TracebackType
from typing import Literal

from rich.console import Console, RenderableType
from rich.live import Live
from rich.padding import Padding
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from opentide.cli.ui.glyphs import glyph
from opentide.cli.ui.layout import Cropped, columns
from opentide.cli.ui.mode import OutputMode, get_mode
from opentide.cli.ui.terminal_progress import TerminalProgress
from opentide.core import progress as engine_progress

StepStatus = Literal["running", "ok", "failed", "skipped"]

_GLYPH = {"ok": "ok", "failed": "failed", "skipped": "disable"}
_STYLE = {"ok": "bold green", "failed": "bold red", "skipped": "dim", "running": "bold cyan"}


def plural(count: int, noun: str, plural_noun: str | None = None) -> str:
    """``1 file``, ``7 files``, ``0 rules``."""
    return f"{count} {noun if count == 1 else (plural_noun or noun + 's')}"


def seconds_text(seconds: float) -> str:
    """``0.3s``, ``12.4s``, ``2m05s``."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(round(seconds)), 60)
    return f"{minutes}m{rest:02d}s"


@dataclass
class Step:
    """One unit of work in a :class:`Checklist`, and what it produced."""

    name: str
    #: What the step produced, in *unit*s; ``None`` when it does not count anything.
    count: int | None = None
    unit: str = "file"
    #: Where the output went, as the reader should see it (``.opentide/schemas/``).
    where: str | None = None
    #: The engine stage running now, or a short note on a finished step.
    detail: str = ""
    status: StepStatus = "running"
    seconds: float = 0.0
    started: float = field(default_factory=time.perf_counter, repr=False)

    def done(
        self,
        count: int | None = None,
        *,
        unit: str | None = None,
        where: str | None = None,
        detail: str | None = None,
    ) -> None:
        """Record what the step produced. The checklist closes it when the block ends."""
        if count is not None:
            self.count = count
        if unit is not None:
            self.unit = unit
        if where is not None:
            self.where = where
        if detail is not None:
            self.detail = detail

    def skip(self, reason: str) -> None:
        """Mark the step as not run, with the reason in place of a count."""
        self.status = "skipped"
        self.detail = reason

    @property
    def facts(self) -> list[str]:
        """The parts a finished step prints after its name, in order."""
        parts: list[str] = []
        if self.count is not None:
            parts.append(plural(self.count, self.unit))
        if self.status == "skipped" and self.detail:
            parts.append(self.detail)
        if self.status != "skipped":
            parts.append(seconds_text(self.seconds))
        if self.where:
            parts.append(self.where)
        return parts

    def to_dict(self) -> dict[str, object]:
        """The step as a result payload carries it."""
        return {
            "name": self.name,
            "status": self.status,
            "count": self.count,
            "unit": self.unit,
            "seconds": round(self.seconds, 3),
            "where": self.where,
        }


def step_line(step: Step, *, encoding: str = "utf-8") -> Text:
    """``✓ schemas · 7 files · 1.6s · .opentide/schemas/`` for ``plain`` and ``agent``."""
    status = step.status if step.status != "running" else "failed"
    line = Text()
    line.append(glyph(_GLYPH[status], encoding=encoding), style=_STYLE[status])
    line.append(" ")
    line.append(step.name)
    separator = f" {glyph('separator', encoding=encoding)} "
    for part in step.facts:
        line.append(separator, style="dim")
        line.append(part)
    return line


def checklist_table(
    steps: Sequence[Step],
    *,
    running: Step | None = None,
    spinner: RenderableType | None = None,
    encoding: str = "utf-8",
) -> RenderableType:
    """The checklist as ``human`` mode draws it: one row per step, the running one last."""
    if running is None:
        # One terminal row per step: a narrow terminal cuts the row, it never wraps it.
        return Cropped(columns([_row(step, encoding) for step in steps], indent=2, right=(2, 3)))
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(justify="right", style="dim", no_wrap=True)
    grid.add_column(justify="right", style="dim", no_wrap=True)
    grid.add_column(style="dim")
    for step in steps:
        status = step.status if step.status != "running" else "failed"
        mark = Text(glyph(_GLYPH[status], encoding=encoding), style=_STYLE[status])
        count = plural(step.count, step.unit) if step.count is not None else ""
        if step.status == "skipped":
            grid.add_row(mark, Text(step.name, style="dim"), "", "", step.detail)
            continue
        grid.add_row(mark, step.name, count, seconds_text(step.seconds), step.where or "")
    if running is not None:
        elapsed = time.perf_counter() - running.started
        grid.add_row(
            spinner or Text("…"),
            Text(running.name, style=_STYLE["running"]),
            plural(running.count, running.unit) if running.count is not None else "",
            seconds_text(elapsed),
            running.detail or running.where or "",
        )
    return Padding(grid, (0, 0, 0, 2), expand=False)


def _row(step: Step, encoding: str) -> tuple[Text, ...]:
    status = step.status if step.status != "running" else "failed"
    mark = Text(glyph(_GLYPH[status], encoding=encoding), style=_STYLE[status])
    if step.status == "skipped":
        return (mark, Text(step.name, style="dim"), Text(), Text(), Text(step.detail, style="dim"))
    return (
        mark,
        Text(step.name, style="bold"),
        Text(plural(step.count, step.unit) if step.count is not None else "", style="dim"),
        Text(seconds_text(step.seconds), style="dim"),
        Text(step.where or "", style="dim"),
    )


class Checklist:
    """The steps of one command run, shown as they finish.

    Use as a context manager, then wrap each unit of work in :meth:`step`::

        with Checklist(total=6) as checklist:
            with checklist.step("schemas", where=".opentide/schemas/") as step:
                count = generate_schemas()
                step.done(count)

    A step that raises is marked failed and the exception propagates. *total*
    is how many steps the run expects, when known, for a percentage display.
    """

    def __init__(
        self,
        console: Console | None = None,
        *,
        mode: OutputMode | None = None,
        quiet: bool | None = None,
        total: int | None = None,
    ) -> None:
        from opentide.core.logging.config import current_config, get_console

        self.console = console or get_console()
        self.mode = mode or get_mode()
        self.quiet = current_config().quiet if quiet is None else quiet
        self.total = total
        self.steps: list[Step] = []
        self.current: Step | None = None
        self._live: Live | None = None
        self._spinner = Spinner("dots", style=_STYLE["running"])
        self._stack = ExitStack()
        self._terminal: TerminalProgress | None = None

    @property
    def silent(self) -> bool:
        """Whether nothing is drawn: JSON, MCP or ``--quiet``."""
        return self.quiet or self.mode in (OutputMode.JSON, OutputMode.MCP)

    @property
    def live(self) -> bool:
        """Whether the checklist animates (``human`` mode only)."""
        return not self.silent and self.mode is OutputMode.HUMAN

    @property
    def completed(self) -> int:
        """Steps finished so far, failed and skipped included."""
        return len(self.steps)

    def __enter__(self) -> Checklist:
        self._stack.enter_context(engine_progress.listen(self._stage))
        if self.live:
            self._terminal = self._stack.enter_context(
                TerminalProgress(self.console, total=self.total, mode=self.mode, quiet=False)
            )
            self._live = Live(
                get_renderable=self._renderable,
                console=self.console,
                refresh_per_second=8,
                transient=True,
                redirect_stdout=False,
                redirect_stderr=False,
            )
            self._live.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stack.close()
        self._terminal = None
        if self._live is not None:
            self._live.stop()
            self._live = None
            if self.steps:
                self.console.print(self._final())

    @contextmanager
    def step(
        self, name: str, *, where: str | None = None, unit: str = "file"
    ) -> Generator[Step, None, None]:
        """Run one step. Its row prints when the block ends, failed if it raised."""
        step = Step(name=name, where=where, unit=unit)
        self.current = step
        try:
            yield step
        except BaseException:
            step.status = "failed"
            raise
        else:
            if step.status == "running":
                step.status = "ok"
        finally:
            step.seconds = time.perf_counter() - step.started
            if step.status != "skipped":
                step.detail = ""
            self.current = None
            self.steps.append(step)
            self._finished(step)

    def _stage(self, name: str) -> None:
        if self.current is not None:
            self.current.detail = name

    def _finished(self, step: Step) -> None:
        if self._terminal is not None:
            self._terminal.update(self.completed)
        if self.silent:
            return
        if self._live is not None:
            self._live.refresh()
            return
        self.console.print(step_line(step, encoding=self._encoding), soft_wrap=True)

    @property
    def _encoding(self) -> str:
        return self.console.encoding or "utf-8"

    def _renderable(self) -> RenderableType:
        return checklist_table(
            self.steps, running=self.current, spinner=self._spinner, encoding=self._encoding
        )

    def _final(self) -> RenderableType:
        return checklist_table(self.steps, encoding=self._encoding)
