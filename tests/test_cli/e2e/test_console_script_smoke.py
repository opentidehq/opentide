"""Subprocess smoke tests for console script entry points."""

from __future__ import annotations

import json
import os

import pytest

# These must run as real subprocesses. `pytest-console-scripts` defaults to
# `inprocess`, which loads the entry point as a function and therefore exercises the
# same path as the in-process `CliRunner` tests. Only a real child process makes the
# console script `__main__`, which is what surfaces import-time failures such as
# multiprocessing `spawn` re-entering the entry point. A mark takes precedence over
# both the ini setting and `--script-launch-mode`.
pytestmark = [
    pytest.mark.cli_smoke,
    pytest.mark.script_launch_mode("subprocess"),
]


def _assert_populated_workspace(counts: dict[str, int]) -> None:
    """Fail if the console script indexed a trivial workspace.

    The smoke layer previously ran against the default empty fixture workspace, so
    object parsing never engaged and startup regressions went unnoticed. Keep the
    corpus above four objects, the count that used to select the parallel path.
    """
    assert sum(counts.values()) > 4, f"smoke workspace is too small to be meaningful: {counts}"


def test_opentide_console_script_help(script_runner, tide_corpus_repo) -> None:
    result = script_runner.run(["opentide", "--help"])
    assert result.returncode == 0, result.stderr
    assert "validate" in result.stdout


def test_opentide_console_script_json_is_single_document(script_runner, tide_corpus_repo) -> None:
    result = script_runner.run(["opentide", "--json", "info"])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert "counts" in payload
    _assert_populated_workspace(payload["counts"])


_COLOUR_ENV = (
    "FORCE_COLOR",
    "NO_COLOR",
    "TTY_COMPATIBLE",
    "CLICOLOR_FORCE",
    "PY_COLORS",
    "GITHUB_ACTIONS",
)


def _terminal_env(colour_env: dict[str, str]) -> dict[str, str]:
    """A user's terminal type, minus inherited colour knobs; ``TERM=dumb`` hides escapes."""
    env = {k: v for k, v in os.environ.items() if k not in _COLOUR_ENV}
    return env | {"TERM": "xterm-256color", **colour_env}


@pytest.mark.parametrize(
    ("flags", "colour_env"),
    [
        pytest.param([], {}, id="default"),
        pytest.param(["--no-color"], {}, id="no-color-flag"),
        pytest.param([], {"FORCE_COLOR": "0"}, id="FORCE_COLOR=0"),
        pytest.param(["--no-color"], {"FORCE_COLOR": "1"}, id="no-color-over-FORCE_COLOR=1"),
    ],
)
def test_opentide_console_script_redirect_has_no_ansi(
    script_runner, tide_corpus_repo, flags: list[str], colour_env: dict[str, str]
) -> None:
    """Asking for less colour must never put escapes into a pipe.

    Rich forces a terminal for any non-empty ``FORCE_COLOR``, ``"0"`` included,
    so ``--no-color`` (which exported ``FORCE_COLOR=0``) and a user's own
    ``FORCE_COLOR=0`` both wrote bold/italic SGR codes into redirected output.
    ``TERM=dumb`` hides that, so the child gets the terminal type a user has.
    """
    result = script_runner.run(["opentide", *flags, "info"], env=_terminal_env(colour_env))
    assert result.returncode == 0, result.stderr
    assert "OpenTide Info" in result.stdout
    assert "\x1b[" not in result.stdout
    assert "\x1b[" not in result.stderr


@pytest.mark.parametrize(
    ("argv", "colour_env"),
    [
        pytest.param(["--help"], {"FORCE_COLOR": "0"}, id="FORCE_COLOR=0"),
        pytest.param(["--no-color", "--help"], {"GITHUB_ACTIONS": "true"}, id="root-help"),
        pytest.param(
            ["--no-color", "setup", "--help"], {"GITHUB_ACTIONS": "true"}, id="subcommand-help"
        ),
        pytest.param(
            ["setup", "--help"], {"NO_COLOR": "1", "GITHUB_ACTIONS": "true"}, id="NO_COLOR"
        ),
    ],
)
def test_typer_help_in_a_pipe_honours_less_colour(
    script_runner, tide_corpus_repo, argv: list[str], colour_env: dict[str, str]
) -> None:
    """Typer renders help itself and fixes ``FORCE_TERMINAL`` at import.

    It forces a terminal for any non-empty ``FORCE_COLOR`` or under
    ``GITHUB_ACTIONS``, and root ``--help`` exits before any callback runs, so
    every documented ``--help`` sample in CI came back full of escapes.
    """
    result = script_runner.run(["opentide", *argv], env=_terminal_env(colour_env))
    assert result.returncode == 0, result.stderr
    assert "Usage" in result.stdout
    assert "\x1b[" not in result.stdout


@pytest.mark.parametrize(
    "colour_env",
    [
        pytest.param({"FORCE_COLOR": "1"}, id="FORCE_COLOR=1"),
        pytest.param({"GITHUB_ACTIONS": "true"}, id="GITHUB_ACTIONS"),
    ],
)
def test_typer_help_still_colours_when_asked(
    script_runner, tide_corpus_repo, colour_env: dict[str, str]
) -> None:
    """Control for the pipe checks: forcing colour must keep working."""
    result = script_runner.run(["opentide", "--help"], env=_terminal_env(colour_env))
    assert result.returncode == 0, result.stderr
    assert "\x1b[" in result.stdout


def test_opentide_console_script_validates_corpus(script_runner, tide_corpus_repo) -> None:
    result = script_runner.run(["opentide", "--json", "validate", "--strict"])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["report"]["stats"]["objects_checked"] > 4
