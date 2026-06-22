"""Tests for CLI context."""

from __future__ import annotations

from pathlib import Path

from opentide.cli.context import CliContext


def test_cli_context_apply_environment_sets_repo_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("OPENTIDE_REPO_ROOT", raising=False)
    ctx = CliContext(repo=tmp_path)
    ctx.apply_environment()
    import os

    assert os.environ["OPENTIDE_REPO_ROOT"] == str(tmp_path)


def test_cli_context_set_deployment_plan() -> None:
    import os

    ctx = CliContext()
    ctx.set_deployment_plan("staging")
    assert os.environ["DEPLOYMENT_PLAN"] == "STAGING"
