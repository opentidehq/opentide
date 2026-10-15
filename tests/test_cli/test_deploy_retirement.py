"""A PRODUCTION deploy retires DISABLED and REMOVED rules by default (#548).

The deployment spec defines ``DISABLEMENT`` as "any active deployment of the
rule is disabled" and ``DELETION`` as removal from the platform, and the
PRODUCTION allow-list includes both. ``--keep-deprecated`` defaulted to off,
so those rules were dropped before the allow-list was consulted and a
retirement never reached the platform.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_cli.test_deploy_production_base import _catalogue, _commit, _env, _git
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.deploy import keeps_deprecated
from opentide.models.deployment_enums import DeploymentStrategy

runner = CliRunner()

SENTINEL_RULE = "00000000-0000-4000-8003-000000000001"


def _retire(tmp_path: Path, status: str) -> tuple[Path, str]:
    repo, rules = _catalogue(tmp_path)
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "catalogue", "2026-01-01T00:00:00+00:00")
    rule = rules / "rule-0001-sentinel-kql.yaml"
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("status: STAGING", f"status: {status}"),
        encoding="utf-8",
    )
    _commit(repo, f"retire the Sentinel rule as {status}", "2026-01-02T00:00:00+00:00")
    return repo, _git(repo, "rev-parse", "HEAD")


@pytest.fixture(autouse=True)
def _fresh_registry() -> object:
    from tests.corpus_support import clear_runtime_caches

    clear_runtime_caches()
    yield
    clear_runtime_caches()


@pytest.mark.parametrize("status", ["DISABLED", "REMOVED"])
def test_production_plan_deploys_a_retired_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, status: str
) -> None:
    del git_home
    repo, head = _retire(tmp_path, status)
    monkeypatch.chdir(repo)

    result = runner.invoke(
        app, ["--json", "deploy", "--dry-run", "--plan", "PRODUCTION"], env=_env(repo, head)
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["plan"] == {"sentinel": [SENTINEL_RULE]}


def test_drop_deprecated_restores_the_old_production_behaviour(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path
) -> None:
    del git_home
    repo, head = _retire(tmp_path, "REMOVED")
    monkeypatch.chdir(repo)

    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--plan", "PRODUCTION", "--drop-deprecated"],
        env=_env(repo, head),
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "skipped"
    assert payload["plan"] == {}


@pytest.mark.parametrize(
    ("plan", "requested", "expected"),
    [
        (DeploymentStrategy.PRODUCTION, None, True),
        (DeploymentStrategy.STAGING, None, False),
        (DeploymentStrategy.FULL, None, False),
        (DeploymentStrategy.PRODUCTION, False, False),
        (DeploymentStrategy.FULL, True, True),
    ],
)
def test_keep_deprecated_defaults_on_for_production_only(
    plan: DeploymentStrategy, requested: bool | None, expected: bool
) -> None:
    assert keeps_deprecated(plan, requested) is expected
