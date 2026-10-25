"""Progress in the terminal's tab and taskbar (OSC 9;4), for long runs in ``human`` mode.

Windows Terminal, Ghostty, kitty, WezTerm and iTerm2 read
``ESC ] 9 ; 4 ; <state> ; <percent> ESC \\`` and show a bar in the tab or the
taskbar. A :class:`TerminalProgress` sends it while a command runs and clears
it when the block ends, on success, on an exception and on Ctrl-C alike.

It is sent only when all of these hold:

- the output mode is ``human`` and ``--quiet`` is off;
- the console's stream is itself a terminal: ``FORCE_COLOR`` makes Rich treat
  a pipe as one, but it asks for colour, not for control sequences in a log;
- ``OPENTIDE_PROGRESS`` is not false (``0``, ``false``, ``no``, ``off``);
- the terminal is one that reads it (:func:`detected`), or ``OPENTIDE_PROGRESS``
  is true (``1``, ``true``, ``yes``, ``on``).

iTerm2 before 3.6 reads a bare OSC 9 as a desktop notification, so it is
recognised only from ``TERM_PROGRAM_VERSION`` 3.6 on, and Ghostty from 1.2,
the first release with OSC 9;4. An older or unknown version gets nothing
unless ``OPENTIDE_PROGRESS`` is true.

Inside tmux (``TMUX`` set) the sequence is wrapped for passthrough, which
tmux forwards when ``allow-passthrough`` is on.

:class:`opentide.cli.ui.progress.Checklist` owns one for every command that
shows steps; a command without a checklist (``share``) opens one directly.
Only the outermost one draws, so a nested block cannot clear its parent's bar.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from contextlib import suppress
from types import TracebackType

from rich.console import Console
from rich.control import Control
from rich.segment import Segment

from opentide.cli.ui.mode import OutputMode, _is_tty, get_mode
from opentide.core.runtime import boolean_env

#: Environment variable: false disables the sequence, true sends it to any terminal.
PROGRESS_ENV = "OPENTIDE_PROGRESS"

# OSC 9;4 states.
CLEAR = 0
VALUE = 1
INDETERMINATE = 3

#: ``TERM_PROGRAM`` values of terminals that read OSC 9;4.
TERM_PROGRAMS = frozenset({"ghostty", "WezTerm", "iTerm.app"})
#: The first ``TERM_PROGRAM_VERSION`` that reads OSC 9;4, where older ones do not.
MINIMUM_VERSIONS: dict[str, tuple[int, int]] = {"iTerm.app": (3, 6), "ghostty": (1, 2)}
#: ``TERM`` values of terminals that read OSC 9;4 in every version that sets them.
TERMS = frozenset({"xterm-kitty"})
#: Variables the outer terminal exports that survive into a tmux pane, where
#: tmux replaces ``TERM`` and ``TERM_PROGRAM`` with its own.
_OUTER_TERMINAL_MARKERS = ("KITTY_WINDOW_ID", "WEZTERM_PANE")
_VERSION = re.compile(r"\s*(\d+)\.(\d+)")

_running: list[TerminalProgress] = []


def detected(env: Mapping[str, str] | None = None) -> bool:
    """Whether the environment names a terminal that reads OSC 9;4.

    ``TERM=xterm-ghostty`` alone (over SSH, say) carries no version, so it is
    not enough; nor is Ghostty inside tmux, where tmux replaces
    ``TERM_PROGRAM_VERSION``. iTerm2 inside tmux gives its version in
    ``LC_TERMINAL_VERSION``.
    """
    env = os.environ if env is None else env
    if env.get("WT_SESSION"):
        return True
    program = env.get("TERM_PROGRAM", "")
    if program in TERM_PROGRAMS:
        return _recent(program, env.get("TERM_PROGRAM_VERSION"))
    if env.get("TERM") in TERMS:
        return True
    if env.get("TMUX"):
        if env.get("LC_TERMINAL") == "iTerm2":
            return _recent("iTerm.app", env.get("LC_TERMINAL_VERSION"))
        return any(env.get(name) for name in _OUTER_TERMINAL_MARKERS)
    return False


def _recent(program: str, version: str | None) -> bool:
    """Whether *version* of *program* reads OSC 9;4; an unknown version does not."""
    minimum = MINIMUM_VERSIONS.get(program)
    if minimum is None:
        return True
    match = _VERSION.match(version or "")
    return match is not None and (int(match.group(1)), int(match.group(2))) >= minimum


def sequence(state: int, percent: int = 0, *, tmux: bool = False) -> str:
    """``ESC ] 9 ; 4 ; state ; percent ESC \\``, wrapped for tmux passthrough when *tmux*."""
    osc = f"\x1b]9;4;{state};{percent}\x1b\\"
    if tmux:
        return "\x1bPtmux;" + osc.replace("\x1b", "\x1b\x1b") + "\x1b\\"
    return osc


def enabled(
    console: Console,
    *,
    mode: OutputMode | None = None,
    quiet: bool = False,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Whether a run on *console* sends OSC 9;4 (see the module docstring)."""
    env = os.environ if env is None else env
    setting = boolean_env(PROGRESS_ENV, env)
    if setting is False or quiet:
        return False
    # The stream itself, not ``console.is_terminal``: FORCE_COLOR sets that on a pipe.
    if (mode or get_mode()) is not OutputMode.HUMAN or not _is_tty(console.file):
        return False
    return setting is True or detected(env)


class _Raw(Control):
    """A control sequence Rich has no code for, written as-is to a terminal.

    Going through :meth:`Console.control` keeps it inside the console's lock,
    so it never lands in the middle of a ``Live`` refresh.
    """

    def __init__(self, text: str) -> None:
        self.segment = Segment(text, None, [])


class TerminalProgress:
    """A tab or taskbar progress bar for the length of a ``with`` block.

    *total* is how many units the run expects; :meth:`update` reports how
    many are done. Without a *total* (or with one unit) the bar is
    indeterminate, since a single unit has no meaningful percentage.
    """

    def __init__(
        self,
        console: Console | None = None,
        *,
        total: int | None = None,
        mode: OutputMode | None = None,
        quiet: bool | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        from opentide.core.logging.config import current_config, get_console

        self.console = console or get_console()
        self.total = total
        self.mode = mode
        self.quiet = current_config().quiet if quiet is None else quiet
        self.env = os.environ if env is None else env
        self.active = False

    @property
    def tmux(self) -> bool:
        return bool(self.env.get("TMUX"))

    def __enter__(self) -> TerminalProgress:
        if not _running and enabled(self.console, mode=self.mode, quiet=self.quiet, env=self.env):
            self.active = True
            self.update(0)
        _running.append(self)
        return self

    def update(self, completed: int) -> None:
        """Show *completed* units of :attr:`total` done."""
        if not self.active:
            return
        if self.total is None or self.total <= 1:
            self._send(INDETERMINATE)
            return
        percent = max(0, min(100, completed * 100 // self.total))
        self._send(VALUE, percent)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self in _running:
            _running.remove(self)
        if self.active:
            self.active = False
            self._send(CLEAR)

    def _send(self, state: int, percent: int = 0) -> None:
        # A closed terminal raises; the bar is not worth a crash.
        with suppress(OSError, ValueError):
            self.console.control(_Raw(sequence(state, percent, tmux=self.tmux)))
