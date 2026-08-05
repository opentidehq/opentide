"""Subprocess smoke tests for console script entry points."""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.cli_smoke


def test_opentide_console_script_help(script_runner) -> None:
    result = script_runner.run(["opentide", "--help"])
    assert result.returncode == 0
    assert "validate" in result.stdout


def test_opentide_console_script_json_is_single_document(script_runner) -> None:
    result = script_runner.run(["opentide", "--json", "info"])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert "counts" in payload


def test_opentide_console_script_redirect_has_no_ansi(script_runner) -> None:
    result = script_runner.run(["opentide", "info"])
    assert result.returncode == 0, result.stderr
    assert "\x1b[" not in result.stdout
    assert "\x1b[" not in result.stderr
