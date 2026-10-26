"""OSC 9;4 tab and taskbar progress: when it is sent, what it says, and that it is cleared."""

from __future__ import annotations

import io
import re

import pytest
from rich.console import Console

from opentide.cli.ui import terminal_progress
from opentide.cli.ui.mode import OutputMode
from opentide.cli.ui.progress import Checklist
from opentide.cli.ui.terminal_progress import TerminalProgress, detected, enabled, sequence

GHOSTTY = {"TERM_PROGRAM": "ghostty", "TERM_PROGRAM_VERSION": "1.2.0"}
_OSC = re.compile(r"\x1b\]9;4;(\d);(\d+)\x1b\\")


class _Terminal(io.StringIO):
    """A captured stream that says it is a terminal, as a real TTY does."""

    def isatty(self) -> bool:
        return True


def _console(*, terminal: bool = True) -> tuple[Console, io.StringIO]:
    stream = _Terminal() if terminal else io.StringIO()
    return Console(file=stream, force_terminal=terminal, width=80), stream


def _states(text: str) -> list[tuple[int, int]]:
    return [(int(state), int(percent)) for state, percent in _OSC.findall(text)]


@pytest.mark.parametrize(
    "env",
    [
        {"WT_SESSION": "5c3f"},
        {"TERM_PROGRAM": "ghostty", "TERM_PROGRAM_VERSION": "1.2.0"},
        {"TERM_PROGRAM": "ghostty", "TERM_PROGRAM_VERSION": "1.10.3-main+0a1b2c"},
        {"TERM_PROGRAM": "WezTerm"},
        {"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.6.6"},
        {"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.6.10"},
        {"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.7"},
        {"TERM": "xterm-kitty"},
        {"TMUX": "/tmp/tmux-1/default,1,0", "TERM_PROGRAM": "tmux", "KITTY_WINDOW_ID": "1"},
        {
            "TMUX": "/tmp/tmux-1/default,1,0",
            "LC_TERMINAL": "iTerm2",
            "LC_TERMINAL_VERSION": "3.6.6",
        },
    ],
    ids=lambda env: "+".join(f"{key}={value}" for key, value in env.items()),
)
def test_detects_terminals_that_read_osc_9_4(env: dict[str, str]) -> None:
    assert detected(env)


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"TERM": "xterm-256color"},
        {"TERM_PROGRAM": "Apple_Terminal"},
        {"TERM_PROGRAM": "vscode"},
        {"TMUX": "/tmp/tmux-1/default,1,0", "TERM_PROGRAM": "tmux"},
        # Outside tmux, a variable left over from another terminal proves nothing.
        {"KITTY_WINDOW_ID": "1", "TERM": "xterm-256color"},
        # iTerm2 before 3.6.6 posts each bare OSC 9 as a desktop notification.
        {"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.5.14"},
        {"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.6.0"},
        {"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.6.5"},
        {"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.6"},
        {"TERM_PROGRAM": "iTerm.app"},
        {"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "nightly"},
        {
            "TMUX": "/tmp/tmux-1/default,1,0",
            "LC_TERMINAL": "iTerm2",
            "LC_TERMINAL_VERSION": "3.6.5",
        },
        {"TMUX": "/tmp/tmux-1/default,1,0", "LC_TERMINAL": "iTerm2"},
        # Ghostty before 1.2, or with no version to tell.
        {"TERM_PROGRAM": "ghostty", "TERM_PROGRAM_VERSION": "1.1.3"},
        {"TERM_PROGRAM": "ghostty"},
        {"TERM": "xterm-ghostty"},
        {"TMUX": "/tmp/tmux-1/default,1,0", "GHOSTTY_RESOURCES_DIR": "/usr/share/ghostty"},
    ],
    ids=lambda env: "+".join(f"{key}={value}" for key, value in env.items()) or "empty",
)
def test_other_terminals_get_nothing(env: dict[str, str]) -> None:
    assert not detected(env)


def test_sequence_and_tmux_passthrough() -> None:
    assert sequence(1, 50) == "\x1b]9;4;1;50\x1b\\"
    assert sequence(0) == "\x1b]9;4;0;0\x1b\\"
    assert sequence(3, tmux=True) == "\x1bPtmux;\x1b\x1b]9;4;3;0\x1b\x1b\\\x1b\\"


def test_enabled_only_in_human_mode_on_a_terminal() -> None:
    terminal, _ = _console()
    pipe, _ = _console(terminal=False)
    assert enabled(terminal, mode=OutputMode.HUMAN, env=GHOSTTY)
    for mode in (OutputMode.PLAIN, OutputMode.AGENT, OutputMode.JSON, OutputMode.MCP):
        assert not enabled(terminal, mode=mode, env=GHOSTTY), mode
    assert not enabled(pipe, mode=OutputMode.HUMAN, env=GHOSTTY)
    assert not enabled(terminal, mode=OutputMode.HUMAN, quiet=True, env=GHOSTTY)
    assert not enabled(terminal, mode=OutputMode.HUMAN, env={})


@pytest.mark.parametrize("value", ["0", "false", "no", "off"])
def test_opentide_progress_false_disables_it(value: str) -> None:
    console, _ = _console()
    assert not enabled(console, mode=OutputMode.HUMAN, env={**GHOSTTY, "OPENTIDE_PROGRESS": value})


def test_opentide_progress_true_sends_it_to_any_terminal() -> None:
    console, _ = _console()
    env = {"TERM": "xterm-256color", "OPENTIDE_PROGRESS": "1"}
    assert enabled(console, mode=OutputMode.HUMAN, env=env)
    pipe, _ = _console(terminal=False)
    assert not enabled(pipe, mode=OutputMode.HUMAN, env=env)


def test_opentide_progress_true_overrides_an_old_or_unknown_version() -> None:
    console, _ = _console()
    for env in (
        {"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.5.14"},
        {"TERM_PROGRAM": "ghostty"},
    ):
        assert not enabled(console, mode=OutputMode.HUMAN, env=env)
        assert enabled(console, mode=OutputMode.HUMAN, env={**env, "OPENTIDE_PROGRESS": "1"})


def test_force_color_on_a_redirected_stream_sends_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``FORCE_COLOR`` makes Rich call a pipe a terminal; the bar still stays out of the log."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    stream = io.StringIO()
    console = Console(file=stream, force_terminal=True, width=80)
    assert console.is_terminal
    env = {**GHOSTTY, "FORCE_COLOR": "1"}
    assert not enabled(console, mode=OutputMode.HUMAN, env=env)
    assert not enabled(console, mode=OutputMode.HUMAN, env={**env, "OPENTIDE_PROGRESS": "1"})
    with TerminalProgress(console, total=2, mode=OutputMode.HUMAN, quiet=False, env=env) as bar:
        bar.update(1)
    assert "\x1b]9;4" not in stream.getvalue()


def test_percentage_then_cleared() -> None:
    console, stream = _console()
    with TerminalProgress(console, total=4, mode=OutputMode.HUMAN, quiet=False, env=GHOSTTY) as bar:
        bar.update(1)
        bar.update(3)
        bar.update(9)
    assert _states(stream.getvalue()) == [(1, 0), (1, 25), (1, 75), (1, 100), (0, 0)]


@pytest.mark.parametrize("total", [None, 1])
def test_unknown_or_single_unit_runs_are_indeterminate(total: int | None) -> None:
    console, stream = _console()
    with TerminalProgress(console, total=total, mode=OutputMode.HUMAN, quiet=False, env=GHOSTTY):
        pass
    assert _states(stream.getvalue()) == [(3, 0), (0, 0)]


@pytest.mark.parametrize("error", [RuntimeError("boom"), KeyboardInterrupt()])
def test_cleared_when_the_run_raises(error: BaseException) -> None:
    """An exception and Ctrl-C (``KeyboardInterrupt``) leave no bar behind."""
    console, stream = _console()
    with (
        pytest.raises(type(error)),
        TerminalProgress(console, total=3, mode=OutputMode.HUMAN, quiet=False, env=GHOSTTY),
    ):
        raise error
    assert _states(stream.getvalue())[-1] == (0, 0)


def test_nothing_is_sent_when_disabled() -> None:
    console, stream = _console()
    with TerminalProgress(console, total=2, mode=OutputMode.PLAIN, quiet=False, env=GHOSTTY) as bar:
        bar.update(1)
    assert stream.getvalue() == ""


def test_only_the_outermost_block_draws() -> None:
    console, stream = _console()
    outer = TerminalProgress(console, total=2, mode=OutputMode.HUMAN, quiet=False, env=GHOSTTY)
    with outer:
        with TerminalProgress(
            console, total=5, mode=OutputMode.HUMAN, quiet=False, env=GHOSTTY
        ) as inner:
            inner.update(5)
        assert not inner.active
        outer.update(1)
    assert _states(stream.getvalue()) == [(1, 0), (1, 50), (0, 0)]
    assert terminal_progress._running == []  # noqa: SLF001


def test_tmux_wraps_every_sequence() -> None:
    console, stream = _console()
    env = {"TMUX": "/tmp/tmux-1/default,1,0", "WT_SESSION": "5c3f"}
    with TerminalProgress(console, total=2, mode=OutputMode.HUMAN, quiet=False, env=env):
        pass
    text = stream.getvalue()
    assert text == sequence(1, 0, tmux=True) + sequence(0, tmux=True)


def test_a_closed_terminal_does_not_fail_the_run() -> None:
    console, stream = _console()
    progress = TerminalProgress(console, total=2, mode=OutputMode.HUMAN, quiet=False, env=GHOSTTY)
    with progress:
        assert progress.active
        stream.close()
        progress.update(1)


# --------------------------------------------------------------------------
# Through the checklist
# --------------------------------------------------------------------------


def test_checklist_reports_each_finished_step(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTIDE_PROGRESS")
    monkeypatch.setenv("WT_SESSION", "5c3f")
    console, stream = _console()
    with Checklist(console, mode=OutputMode.HUMAN, quiet=False, total=2) as run:
        with run.step("schemas") as step:
            step.done(3)
        with run.step("templates") as step:
            step.done(2)
    assert _states(stream.getvalue()) == [(1, 0), (1, 50), (1, 100), (0, 0)]


def test_checklist_clears_the_bar_when_a_step_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTIDE_PROGRESS")
    monkeypatch.setenv("WT_SESSION", "5c3f")
    console, stream = _console()
    with (
        pytest.raises(RuntimeError),
        Checklist(console, mode=OutputMode.HUMAN, quiet=False, total=3) as run,
        run.step("schemas"),
    ):
        raise RuntimeError("phase failed")
    assert _states(stream.getvalue()) == [(1, 0), (1, 33), (0, 0)]


@pytest.mark.parametrize("mode", [OutputMode.PLAIN, OutputMode.AGENT, OutputMode.JSON])
def test_checklist_sends_nothing_outside_human_mode(
    monkeypatch: pytest.MonkeyPatch, mode: OutputMode
) -> None:
    monkeypatch.delenv("OPENTIDE_PROGRESS")
    monkeypatch.setenv("WT_SESSION", "5c3f")
    console, stream = _console()
    with Checklist(console, mode=mode, quiet=False, total=1) as run, run.step("schemas"):
        pass
    assert "\x1b]9;4" not in stream.getvalue()


def test_checklist_sends_nothing_with_progress_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WT_SESSION", "5c3f")
    console, stream = _console()
    with Checklist(console, mode=OutputMode.HUMAN, quiet=False, total=1) as run, run.step("x"):
        pass
    assert "\x1b]9;4" not in stream.getvalue()
