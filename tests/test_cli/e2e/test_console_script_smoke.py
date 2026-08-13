"""Subprocess smoke tests for console script entry points."""

from __future__ import annotations

import json

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


def test_opentide_console_script_redirect_has_no_ansi(script_runner, tide_corpus_repo) -> None:
    result = script_runner.run(["opentide", "info"])
    assert result.returncode == 0, result.stderr
    assert "\x1b[" not in result.stdout
    assert "\x1b[" not in result.stderr


def test_opentide_console_script_validates_corpus(script_runner, tide_corpus_repo) -> None:
    result = script_runner.run(["opentide", "--json", "validate", "--strict"])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["report"]["stats"]["objects_checked"] > 4
