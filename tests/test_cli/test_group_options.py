"""Group options typed before a subcommand reach it, or are refused.

Each group callback used to return as soon as a subcommand was named, so its
options were dropped without a word: ``share --dry-run push`` pushed for real
and ``deploy --dry-run migrate-state`` edited rule files.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()


@pytest.fixture
def run_share(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    # `opentide.cli.share_app` the attribute is the Typer app, not the module.
    share_app = sys.modules["opentide.cli.share_app"]
    mock = MagicMock(return_value={"message": "ok", "status": "completed"})
    monkeypatch.setattr(share_app, "run_share", mock)
    monkeypatch.setattr(share_app, "render_share", lambda _payload: None)
    return mock


#: Rich wraps a usage error in a panel at the terminal's width (80 on CI runners),
#: breaking the message across borders; render it on one line, uncoloured.
_PLAIN_TERMINAL = {"COLUMNS": "1000", "NO_COLOR": "1", "FORCE_COLOR": None}


def _invoke(tmp_path: Path, *argv: str) -> Any:
    return runner.invoke(app, ["--repo", str(tmp_path), *argv], env=_PLAIN_TERMINAL)


def test_share_options_before_push_reach_push(tmp_path: Path, run_share: MagicMock) -> None:
    result = _invoke(tmp_path, "share", "--dry-run", "--target", "staging", "push")

    assert result.exit_code == 0, result.output
    kwargs = run_share.call_args.kwargs
    assert kwargs["mode"] == "push"
    assert kwargs["dry_run"] is True
    assert kwargs["targets"] == ["staging"]


def test_share_option_the_subcommand_does_not_take_is_refused(
    tmp_path: Path, run_share: MagicMock
) -> None:
    result = _invoke(tmp_path, "share", "--dry-run", "--workers", "4", "status")

    assert result.exit_code == 2
    assert "--dry-run, --workers configure `opentide share` itself" in " ".join(
        result.output.split()
    )
    run_share.assert_not_called()


def test_share_option_given_on_both_sides_is_refused(tmp_path: Path, run_share: MagicMock) -> None:
    result = _invoke(tmp_path, "share", "--target", "a", "push", "--target", "b")

    assert result.exit_code == 2
    assert "Pass --target once" in result.output
    run_share.assert_not_called()


def test_subcommand_help_still_works_after_a_group_option(tmp_path: Path) -> None:
    result = _invoke(tmp_path, "share", "--dry-run", "status", "--help")

    assert result.exit_code == 0, result.output
    assert "Compare the local ledger" in result.output


def test_deploy_dry_run_before_migrate_state_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import opentide.cli.services.migrate_state as migrate_state

    migrate = MagicMock(return_value={"message": "migrated"})
    monkeypatch.setattr(migrate_state, "run_migrate_state", migrate)

    result = _invoke(tmp_path, "deploy", "--dry-run", "migrate-state")

    assert result.exit_code == 2
    assert "--dry-run configures `opentide deploy` itself" in " ".join(result.output.split())
    migrate.assert_not_called()


def test_deploy_dry_run_before_replay_state_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import opentide.ci.state_replay as state_replay

    replay = MagicMock(return_value=0)
    monkeypatch.setattr(state_replay, "main", replay)

    result = _invoke(tmp_path, "deploy", "--dry-run", "replay-state", "HEAD")

    assert result.exit_code == 2
    replay.assert_not_called()


def test_validate_strict_before_query_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    query = MagicMock(return_value={"status": "passed"})
    monkeypatch.setattr("opentide.cli.validate_query_platform", query)

    result = _invoke(tmp_path, "validate", "--strict", "query", "--platform", "sentinel")

    assert result.exit_code == 2
    query.assert_not_called()


def test_validate_file_before_query_reaches_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    query = MagicMock(return_value={"status": "passed"})
    monkeypatch.setattr("opentide.cli.validate_query_platform", query)

    result = _invoke(tmp_path, "validate", "--file", "r.yaml", "query", "--platform", "sentinel")

    assert result.exit_code == 0, result.output
    assert query.call_args.kwargs["files"] == ["r.yaml"]


@pytest.mark.parametrize("group", [["generate", "docs"], ["document"]])
def test_docs_output_before_a_scope_reaches_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, group: list[str]
) -> None:
    document = MagicMock(return_value={"message": "ok"})
    monkeypatch.setattr("opentide.cli.run_document", document)

    result = _invoke(tmp_path, *group, "--output", "out", "--flavor", "plain", "rules")

    assert result.exit_code == 0, result.output
    assert document.call_args.kwargs["output"] == "out"
    assert document.call_args.kwargs["flavor"] == "plain"


def test_docs_scope_flag_before_another_scope_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = MagicMock(return_value={"message": "ok"})
    monkeypatch.setattr("opentide.cli.run_document", document)

    result = _invoke(tmp_path, "generate", "docs", "--threats", "rules")

    assert result.exit_code == 2
    document.assert_not_called()
