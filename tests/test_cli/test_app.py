"""Tests for Typer CLI surface."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()


def test_cli_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "setup",
        "generate",
        "validate",
        "deploy",
        "document",
        "mutate",
        "export",
        "extract",
        "info",
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


def test_generate_subcommands_invoke_services() -> None:
    with patch("opentide.cli.run_generate", return_value={"status": "ok"}) as mock_run:
        for phase in ("schemas", "templates", "vocabs", "snippets", "exports", "playbook-map"):
            result = runner.invoke(app, ["--json", "generate", phase])
            assert result.exit_code == 0, result.stdout
        assert mock_run.call_count == 6
        assert {call.kwargs["phase"] for call in mock_run.call_args_list} == {
            "schemas",
            "templates",
            "vocabs",
            "snippets",
            "exports",
            "playbook-map",
        }


def test_generate_all_runs_full_pipeline() -> None:
    with patch("opentide.cli.run_generate", return_value={"status": "ok"}) as mock_run:
        result = runner.invoke(app, ["--json", "generate"])
    assert result.exit_code == 0
    mock_run.assert_called_once()


def test_validate_group_default_check() -> None:
    with (
        patch("opentide.cli.run_validate", return_value={"checks": {}}) as mock_validate,
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "validate"])
    assert result.exit_code == 0
    mock_validate.assert_called_once()


def test_validate_query_supported_platform() -> None:
    with (
        patch(
            "opentide.cli.validate_query_platform",
            return_value={"platform": "sentinel", "status": "passed", "supported": True},
        ) as mock_query,
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "validate", "query", "--platform", "sentinel"])
    assert result.exit_code == 0
    mock_query.assert_called_once()


def test_deploy_dry_run_json() -> None:
    with (
        patch("opentide.cli.run_deploy", return_value={"status": "completed", "dry_run": True}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "deploy", "--dry-run"])
    assert result.exit_code == 0


def test_export_navigator_json() -> None:
    with (
        patch("opentide.cli.run_export", return_value={"target": "navigator"}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "export", "navigator"])
    assert result.exit_code == 0


def test_mutate_promote_json() -> None:
    with (
        patch("opentide.cli.run_mutate", return_value={"action": "promote"}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "mutate", "promote"])
    assert result.exit_code == 0


def test_document_rules_json() -> None:
    with (
        patch("opentide.cli.run_document", return_value={"scope": "rules"}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "document", "rules"])
    assert result.exit_code == 0


def test_extract_sentinel_json() -> None:
    with (
        patch("opentide.cli.run_extract", return_value={"import": "sentinel"}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "extract", "sentinel"])
    assert result.exit_code == 0


def test_generate_docs_subcommand() -> None:
    with (
        patch("opentide.cli.run_generate_docs") as mock_docs,
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "generate", "docs", "--rules"])
    assert result.exit_code == 0
    mock_docs.assert_called_once_with(rules=True, threats=False, objectives=False)


def test_info_rules_section_json() -> None:
    with (
        patch(
            "opentide.cli.collect_info",
            return_value={"rules": ["r1"], "counts": {}, "platforms": []},
        ),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "info", "rules"])
    assert result.exit_code == 0
    assert "r1" in result.stdout


def test_deploy_metadata_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "STAGING")
    with (
        patch("opentide.cli.run_deploy", return_value={"status": "skipped"}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "deploy", "metadata", "--platform", "splunk"])
    assert result.exit_code == 0
    assert "splunk" in result.stdout
