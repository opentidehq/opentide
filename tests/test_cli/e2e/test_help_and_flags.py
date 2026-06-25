"""CLI E2E: help text and global flags."""

from __future__ import annotations

import pytest
from tests.test_cli.conftest import assert_json_ok

pytestmark = pytest.mark.cli_e2e


def test_cli_help_lists_commands(cli_runner, invoke_cli) -> None:
    result = invoke_cli("--help", json_output=False)
    assert result.exit_code == 0
    for command in (
        "setup",
        "generate",
        "validate",
        "deploy",
        "info",
    ):
        assert command in result.stdout


def test_json_suppresses_banner(cli_runner, tide_corpus_repo) -> None:
    from opentide.cli import app

    result = cli_runner.invoke(
        app,
        ["--json", "--repo", str(tide_corpus_repo), "info"],
    )
    payload = assert_json_ok(result)
    assert "counts" in payload
    assert "OpenTide" not in result.stdout


def test_no_color_info_renders_plain_text(cli_runner, tide_corpus_repo) -> None:
    from opentide.cli import app

    result = cli_runner.invoke(
        app,
        ["--no-color", "--repo", str(tide_corpus_repo), "info"],
    )
    assert result.exit_code == 0
    assert "enabled" in result.stdout.lower()
