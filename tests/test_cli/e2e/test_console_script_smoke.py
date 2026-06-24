"""Subprocess smoke tests for console script entry points."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.cli_smoke


def test_opentide_console_script_help(script_runner) -> None:
    result = script_runner.run(["opentide", "--help"])
    assert result.returncode == 0
    assert "validate" in result.stdout
