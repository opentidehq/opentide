"""CLI E2E: a rule with a vendor id on any block is refused for every platform (RFC 0010 §3).

The guard lives in ``make_deploy_plan``, so it covers every deployer, ``deploy
--dry-run`` and ``validate query --live``, which all build their plan there.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS, write_rule_variant
from tests.test_cli.conftest import parse_cli_json
from tests.test_cli.e2e.helpers import uncomment_tenants

pytestmark = pytest.mark.cli_e2e

REFUSED = CORPUS_RULE_UUIDS["sentinel"]
CLEAN = "00000000-0000-4000-8003-000000000301"


@pytest.fixture(autouse=True)
def _deployment_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


def _rules(repo: Path) -> Path:
    return repo / "objects" / "rules"


def _give_sentinel_rule_a_defender_rule_id(repo: Path) -> None:
    """Rule 0001 deploys to Sentinel; its Defender block still carries ``rule_id``."""
    rules = _rules(repo)
    sentinel = next(p for p in rules.glob("*.yaml") if REFUSED in p.read_text(encoding="utf-8"))
    defender = next(p for p in rules.glob("rule-0002-*.yaml"))
    block = defender.read_text(encoding="utf-8").split("configurations:\n", 1)[1]
    block = block.replace("status: STAGING", "status: DESIGN")
    block = block.replace(
        "  defender_for_endpoint:\n",
        "  defender_for_endpoint:\n    rule_id:\n      contoso: 7590\n",
    )
    sentinel.write_text(sentinel.read_text(encoding="utf-8") + block, encoding="utf-8")


def _mock_sentinel(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """The Sentinel engine, which is what would build the tenant client."""
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return {"sentinel": deployer} if "sentinel" in set(platforms) else {}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    return deployer


def _deploy(invoke_cli, *extra: str):
    return invoke_cli(
        "deploy", "--platform", "sentinel", "--plan", "FULL", "--skip-promotion", *extra
    )


def test_sentinel_deploy_refuses_a_rule_with_a_defender_rule_id(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _give_sentinel_rule_a_defender_rule_id(tide_corpus_repo)
    write_rule_variant(_rules(tide_corpus_repo), "rule-0301-clean.yaml", CLEAN)
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/systems/sentinel.toml")
    deployer = _mock_sentinel(monkeypatch)

    result = _deploy(invoke_cli)

    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["status"] == "failed"
    assert REFUSED not in payload["plan"]["sentinel"]
    assert CLEAN in payload["plan"]["sentinel"]
    deployer.deploy.assert_called_once()
    assert REFUSED not in deployer.deploy.call_args.kwargs["mdr_deployment"]
    assert CLEAN in deployer.deploy.call_args.kwargs["mdr_deployment"]
    assert any("external_id_in_rule" in warning for warning in payload["warnings"])
    assert "external_id_in_rule" in result.stderr


def test_a_plan_left_empty_by_the_guard_fails_without_a_client(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _give_sentinel_rule_a_defender_rule_id(tide_corpus_repo)
    for path in _rules(tide_corpus_repo).glob("*.yaml"):
        if REFUSED not in path.read_text(encoding="utf-8"):
            path.unlink()
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/systems/sentinel.toml")
    deployer = _mock_sentinel(monkeypatch)

    result = _deploy(invoke_cli)

    assert result.exit_code == 1, result.stdout + result.stderr
    assert "external_id_in_rule" in parse_cli_json(result)["message"]
    deployer.deploy.assert_not_called()


def test_dry_run_plan_excludes_the_rule_and_fails(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _give_sentinel_rule_a_defender_rule_id(tide_corpus_repo)
    write_rule_variant(_rules(tide_corpus_repo), "rule-0301-clean.yaml", CLEAN)
    deployer = _mock_sentinel(monkeypatch)

    result = _deploy(invoke_cli, "--dry-run")

    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert REFUSED not in payload["plan"]["sentinel"]
    assert CLEAN in payload["plan"]["sentinel"]
    assert all(item["uuid"] != REFUSED for item in payload["payloads"]["sentinel"])
    deployer.deploy.assert_not_called()


def test_live_query_validation_plan_excludes_the_rule(tide_corpus_repo: Path) -> None:
    from opentide.deployment import DeploymentStrategy, make_deploy_plan

    _give_sentinel_rule_a_defender_rule_id(tide_corpus_repo)
    write_rule_variant(_rules(tide_corpus_repo), "rule-0301-clean.yaml", CLEAN)

    plan = make_deploy_plan(DeploymentStrategy.FULL, wide_scope=True, keep_deprecated=False)

    assert all(REFUSED not in uuids for uuids in plan.values())
    assert CLEAN in plan["sentinel"]


def test_platform_left_empty_by_the_guard_fails(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--platform`` narrowing to a platform the guard emptied is a failure, not a skip.

    A clean Sentinel rule keeps the overall plan non-empty, so only the
    Defender slice is empty and the early "nothing to deploy" return is taken.
    """
    _give_sentinel_rule_a_defender_rule_id(tide_corpus_repo)
    for path in _rules(tide_corpus_repo).glob("*.yaml"):
        if REFUSED not in path.read_text(encoding="utf-8"):
            path.unlink()
    write_rule_variant(_rules(tide_corpus_repo), "rule-0301-clean.yaml", CLEAN)
    _mock_sentinel(monkeypatch)

    result = invoke_cli(
        "deploy", "--platform", "defender_for_endpoint", "--plan", "FULL", "--skip-promotion"
    )

    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["status"] == "failed"
    assert payload["plan"] == {}


def test_a_previous_runs_failure_does_not_leak(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for path in _rules(tide_corpus_repo).glob("*.yaml"):
        path.unlink()
    monkeypatch.setenv("DEPLOYMENT_ERROR_RAISED", "1")

    result = _deploy(invoke_cli)

    assert result.exit_code == 0, result.stdout + result.stderr
    assert parse_cli_json(result)["status"] == "skipped"
