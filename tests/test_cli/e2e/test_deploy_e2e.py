"""CLI E2E: deploy dry-run payloads."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from tests.test_cli.conftest import assert_json_ok

pytestmark = pytest.mark.cli_e2e


@pytest.mark.parametrize("platform", ["sentinel", "defender_for_endpoint", "splunk"])
def test_deploy_dry_run_returns_plan_and_payloads(
    invoke_cli,
    corpus_rule_uuids,
    platform: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deployer = MagicMock()

    class _MockDeployTide:
        @property
        def mdr(self) -> dict[str, MagicMock]:
            return {platform: deployer}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        platform,
        "--plan",
        "FULL",
        "--wide",
        "--skip-promotion",
    )
    payload = assert_json_ok(result)
    assert payload["dry_run"] is True
    expected_uuid = corpus_rule_uuids[platform]
    assert expected_uuid in payload["plan"][platform]
    previews = payload["payloads"][platform]
    assert any(item["uuid"] == expected_uuid for item in previews)
    assert previews[0]["api_request"]
    deployer.deploy.assert_not_called()


def test_deploy_dry_run_sentinel_payload_contains_query(
    invoke_cli,
    corpus_rule_uuids,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform = "sentinel"
    deployer = MagicMock()

    class _MockDeployTide:
        @property
        def mdr(self) -> dict[str, MagicMock]:
            return {platform: deployer}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        platform,
        "--plan",
        "FULL",
        "--wide",
        "--skip-promotion",
    )
    payload = assert_json_ok(result)
    previews = payload["payloads"][platform]
    expected_uuid = corpus_rule_uuids[platform]
    preview = next(item for item in previews if item["uuid"] == expected_uuid)
    api_request = preview["api_request"]
    query_text = api_request.get("query") or api_request.get("properties", {}).get("query", "")
    assert "SecurityEvent" in str(query_text)
    assert preview["uuid"] == corpus_rule_uuids[platform]
