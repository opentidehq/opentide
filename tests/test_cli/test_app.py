"""Tests for Typer CLI surface."""

from __future__ import annotations

from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()


def test_cli_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "init",
        "generate",
        "validate",
        "deploy",
        "document",
        "mutate",
        "export",
        "extract",
        "info",
        "ci",
        "migrate",
    ):
        assert command in result.stdout


def test_validate_query_crowdstrike_not_supported() -> None:
    result = runner.invoke(app, ["--json", "validate", "query", "--platform", "crowdstrike"])
    assert result.exit_code != 0
    assert "not supported" in result.stdout.lower() or "not supported" in result.stderr.lower()


def test_validate_query_harfanglab_not_supported() -> None:
    result = runner.invoke(app, ["--json", "validate", "query", "--platform", "harfanglab"])
    assert result.exit_code != 0


def test_info_json_output() -> None:
    result = runner.invoke(app, ["--json", "info"])
    assert result.exit_code == 0
    assert '"counts"' in result.stdout
    assert '"platforms"' in result.stdout
