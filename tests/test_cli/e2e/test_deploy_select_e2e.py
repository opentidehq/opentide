"""CLI E2E: ``deploy --uuid`` and ``--file`` select the rules a run plans (#753)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from unittest.mock import MagicMock

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.conftest import assert_json_ok

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
