"""CLI E2E: ``deploy --uuid`` and ``--file`` select the rules a run plans (#753)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.conftest import assert_json_ok
from tests.test_cli.e2e.helpers import uncomment_tenants

pytestmark = pytest.mark.cli_e2e

SENTINEL = CORPUS_RULE_UUIDS["sentinel"]
SPLUNK = CORPUS_RULE_UUIDS["splunk"]


def _mock_engines(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Stand in for every platform's engine: a dry run sends nothing, and must not try to."""
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return dict.fromkeys(platforms, deployer)

    monkeypatch.setattr("opentide.platforms.plugins.EnabledPlatforms", _MockDeployTide)
    return deployer


def test_uuid_plans_and_renders_only_that_rule(invoke_cli, monkeypatch) -> None:
    deployer = _mock_engines(monkeypatch)
    # The corpus is no git checkout: the git-diff default would fail, so a plan
    # proves --uuid replaced it.
    result = invoke_cli("deploy", "--dry-run", "--strategy", "PREVIEW", "--uuid", SENTINEL)
    payload = assert_json_ok(result)
    assert payload["scope"] == "selected"
    assert payload["plan"] == {"sentinel": [SENTINEL]}
    assert [item["uuid"] for item in payload["payloads"]["sentinel"]] == [SENTINEL]
    assert payload["payloads"]["sentinel"][0]["api_request"]
    assert set(payload["payloads"]) == {"sentinel"}
    deployer.deploy.assert_not_called()


def test_file_and_uuid_select_together(invoke_cli, monkeypatch) -> None:
    _mock_engines(monkeypatch)
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--strategy",
        "PREVIEW",
        "--file",
        "rule-0003-splunk-spl.yaml",
        "--uuid",
        SENTINEL.upper(),
    )
    payload = assert_json_ok(result)
    assert payload["plan"] == {"sentinel": [SENTINEL], "splunk": [SPLUNK]}
    assert {item["uuid"] for items in payload["payloads"].values() for item in items} == {
        SENTINEL,
        SPLUNK,
    }


def test_selection_keeps_the_status_filter(invoke_cli, monkeypatch) -> None:
    """A selected rule still deploys only when a run strategy takes its status."""
    _mock_engines(monkeypatch)
    result = invoke_cli("deploy", "--dry-run", "--strategy", "RELEASE", "--uuid", SENTINEL)
    payload = json.loads(result.stdout)
    assert payload["plan"] == {}
    assert payload["status"] == "skipped"
    assert payload["scope"] == "selected"


@pytest.mark.parametrize("flag", ["--uuid", "--file"])
def test_selection_with_all_is_a_usage_error(
    invoke_cli, refuse_deployment_engines: list[str], flag: str
) -> None:
    value = SENTINEL if flag == "--uuid" else "rule-0001-sentinel-kql.yaml"
    result = invoke_cli("deploy", "--dry-run", "--strategy", "PREVIEW", "--all", flag, value)
    assert result.exit_code == 2, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["failure"]["code"] == "usage_error"
    assert payload["failure"]["argument"] == flag
    assert "--all" in payload["message"]
    assert refuse_deployment_engines == []


def test_a_selection_that_matches_nothing_fails(
    invoke_cli, refuse_deployment_engines: list[str]
) -> None:
    missing = "00000000-0000-4000-8003-0000000dead3"
    result = invoke_cli(
        "deploy", "--dry-run", "--strategy", "PREVIEW", "--uuid", SENTINEL, "--uuid", missing
    )
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["unmatched"] == [missing]
    assert missing in payload["message"]
    assert "plan" not in payload
    assert refuse_deployment_engines == []


def test_a_bad_strategy_is_a_usage_error_before_the_selection_is_checked(
    invoke_cli, refuse_deployment_engines: list[str]
) -> None:
    """A mistyped --strategy is the usage error (exit 2), even with a --uuid that selects
    nothing: the run failed with exit 1 and the unmatched value instead."""
    missing = "00000000-0000-4000-8003-0000000dead3"
    result = invoke_cli("deploy", "--dry-run", "--strategy", "PREVEIW", "--uuid", missing)
    assert result.exit_code == 2, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["failure"]["code"] == "usage_invalid_choice"
    assert payload["failure"]["argument"] == "--strategy"
    assert "unmatched" not in payload
    assert refuse_deployment_engines == []


def test_a_real_release_with_uuid_sends_only_that_rule_and_promotes_nothing(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not a dry run: the selected rule is the only one sent, and RELEASE does not run the
    status promotion over the git diff, which a selection replaces."""
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/platforms/sentinel.toml")
    deployer = _mock_engines(monkeypatch)
    promoted = MagicMock()
    monkeypatch.setattr("opentide.mutation.promotion.PromoteMDR.promote", promoted)
    result = invoke_cli(
        "deploy",
        "--strategy",
        "PREVIEW",
        "--strategy",
        "RELEASE",
        "--uuid",
        SENTINEL,
        extra_env={"OPENTIDE_PROGRESS": "json"},
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["scope"] == "selected"
    promoted.assert_not_called()
    sent = [call.kwargs["mdr_deployment"] for call in deployer.deploy.call_args_list]
    assert sent == [[SENTINEL]]
    events = [
        json.loads(line) for line in result.stderr.splitlines() if line.startswith('{"event"')
    ]
    assert events == [{"event": "progress", "step": "sentinel", "done": 1, "total": 1}]
