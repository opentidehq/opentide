"""Tests for Typer CLI surface."""

from __future__ import annotations

import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()


def test_cli_import_does_not_load_pymisp() -> None:
    """PyMISP logs at import. That must not run for every opentide command."""
    done = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys\nfrom opentide.cli import app\nraise SystemExit('pymisp' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr


def test_cli_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "setup",
        "generate",
        "validate",
        "deploy",
        "share",
        "info",
        "mcp",
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


def test_info_strict_json_reports_parse_errors() -> None:
    payload = {
        "version": "0",
        "repo": "/tmp",
        "counts": {"rules": 0, "threats": 0, "objectives": 0},
        "parse_error_count": 2,
        "platforms": [],
    }
    with patch("opentide.cli.collect_info", return_value=payload):
        result = runner.invoke(app, ["--json", "info", "--strict"])
    assert result.exit_code == 1
    body = json.loads(result.stdout)
    assert body["ok"] is False
    assert body["status"] == "failed"
    assert body["parse_error_count"] == 2
    assert body["message"] == "Repository has objects that failed to load"


def test_info_strict_human_exits_when_objects_fail_to_load() -> None:
    payload = {
        "version": "0",
        "repo": "/tmp",
        "counts": {"rules": 0, "threats": 0, "objectives": 0},
        "parse_error_count": 1,
        "platforms": [],
    }
    with patch("opentide.cli.collect_info", return_value=payload):
        result = runner.invoke(app, ["info", "--strict"])
    assert result.exit_code == 1


def test_generate_subcommands_invoke_services() -> None:
    with patch("opentide.cli.run_generate", return_value={"status": "ok"}) as mock_run:
        for phase in ("schemas", "templates", "vocabs", "snippets"):
            result = runner.invoke(app, ["--json", "generate", phase])
            assert result.exit_code == 0, result.stdout + result.stderr
            assert mock_run.call_args.kwargs["phases"] == [phase]
        result = runner.invoke(app, ["--json", "generate", "exports"])
        assert result.exit_code == 0, result.stdout + result.stderr
        assert mock_run.call_args.kwargs["phase"] == "exports"


def test_generate_runs_several_phases_in_the_given_order() -> None:
    with patch("opentide.cli.run_generate", return_value={"status": "ok"}) as mock_run:
        result = runner.invoke(
            app,
            ["--json", "generate", "schemas", "templates", "vocabs", "snippets"],
        )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_run.call_args.kwargs["phases"] == [
        "schemas",
        "templates",
        "vocabs",
        "snippets",
    ]


def test_nested_generate_commands_stay_commands() -> None:
    for argv in (
        ["generate", "docs", "--help"],
        ["generate", "exports", "--help"],
        ["generate", "extract", "--help"],
        ["generate", "inflight", "--help"],
        ["generate", "explorer", "--help"],
    ):
        result = runner.invoke(app, argv)
        assert result.exit_code == 0, result.stdout + result.stderr


def test_generate_docs_group_invokes_service() -> None:
    with patch("opentide.cli.run_generate_docs", return_value={"status": "ok"}) as mock_docs:
        result = runner.invoke(app, ["--json", "generate", "docs", "--rules"])
    assert result.exit_code == 0
    mock_docs.assert_called_once()


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


def test_validate_failure_emits_json_before_exit() -> None:
    result_payload = {
        "report": {"ok": False, "issues": [{"code": "schema"}]},
        "_exit_code": 1,
    }
    with patch("opentide.cli.run_validate", return_value=result_payload):
        result = runner.invoke(app, ["--json", "validate"])
    assert result.exit_code == 1
    assert '"ok": false' in result.stdout
    assert '"report"' in result.stdout


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


def test_export_playbook_map_legacy_shim() -> None:
    with (
        patch("opentide.cli.services.export.run_playbook_map_export") as mock_run,
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "export", "playbook-map"])
    assert result.exit_code == 0
    mock_run.assert_called_once()


def test_run_playbook_map_export_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.services import export as export_service

    called = MagicMock()
    monkeypatch.setattr("opentide.export.playbook_map.run", called)
    export_service.run_playbook_map_export()
    called.assert_called_once()


def test_generate_exports_navigator_json() -> None:
    with (
        patch("opentide.cli.run_export", return_value={"target": "navigator"}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "generate", "exports", "navigator"])
    assert result.exit_code == 0


def test_document_rules_deprecated_shim() -> None:
    with (
        patch("opentide.cli.run_document", return_value={"scope": "rules"}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "document", "rules"])
    assert result.exit_code == 0


def test_generate_extract_sentinel_json() -> None:
    with (
        patch("opentide.cli.run_extract", return_value={"import": "sentinel"}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "generate", "extract", "sentinel"])
    assert result.exit_code == 0


def test_generate_docs_rules_subcommand() -> None:
    with (
        patch("opentide.cli.run_document", return_value={"scope": "rules"}) as mock_docs,
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "generate", "docs", "rules"])
    assert result.exit_code == 0
    mock_docs.assert_called_once()


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


def test_info_rejects_unknown_section() -> None:
    result = runner.invoke(app, ["--json", "info", "mystery"])
    assert result.exit_code == 1
    assert "Unknown info section" in result.stdout


def test_deploy_metadata_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "STAGING")
    with (
        patch("opentide.cli.run_deploy", return_value={"status": "skipped"}),
        patch("opentide.cli.init_logging"),
        patch("opentide.cli.print_banner"),
    ):
        result = runner.invoke(app, ["--json", "deploy", "metadata", "--platform", "splunk"])
    assert result.exit_code == 2
    assert "not implemented" in result.stdout
