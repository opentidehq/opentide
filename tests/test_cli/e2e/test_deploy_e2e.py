"""CLI E2E: deploy dry-run payloads."""

from __future__ import annotations

from collections.abc import Iterable
from unittest.mock import MagicMock

import pytest
from tests.test_cli.conftest import assert_json_ok

pytestmark = pytest.mark.cli_e2e


def _mock_deployer(monkeypatch: pytest.MonkeyPatch, platform: str) -> MagicMock:
    """Stand in for *platform*'s engine; only the scoped loader is offered."""
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return {platform: deployer} if platform in set(platforms) else {}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    return deployer


@pytest.mark.parametrize("platform", ["sentinel", "defender_for_endpoint", "splunk"])
def test_deploy_dry_run_returns_plan_and_payloads(
    invoke_cli,
    corpus_rule_uuids,
    platform: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deployer = _mock_deployer(monkeypatch, platform)
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


def test_deploy_dry_run_without_plan_or_wide(
    invoke_cli,
    corpus_rule_uuids,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Local CLI: unset DEPLOYMENT_PLAN must not traceback (issue #164)."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    deployer = _mock_deployer(monkeypatch, "sentinel")
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "sentinel",
        "--skip-promotion",
        extra_env={"DEPLOYMENT_PLAN": ""},
    )
    payload = assert_json_ok(result)
    assert payload["dry_run"] is True
    expected_uuid = corpus_rule_uuids["sentinel"]
    assert expected_uuid in payload["plan"]["sentinel"]
    deployer.deploy.assert_not_called()


def test_deploy_dry_run_staging_without_wide_does_not_traceback(
    invoke_cli,
    corpus_rule_uuids,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    deployer = _mock_deployer(monkeypatch, "sentinel")
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "sentinel",
        "--plan",
        "STAGING",
        "--skip-promotion",
    )
    payload = assert_json_ok(result)
    assert payload["dry_run"] is True
    expected_uuid = corpus_rule_uuids["sentinel"]
    assert expected_uuid in payload["plan"]["sentinel"]
    deployer.deploy.assert_not_called()


def test_deploy_dry_run_sentinel_payload_contains_query(
    invoke_cli,
    corpus_rule_uuids,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform = "sentinel"
    _mock_deployer(monkeypatch, platform)
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


def test_deploy_loads_only_the_requested_engine(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No DeployTide mock: the real loader must not build every platform's engine.

    Loading all seven deployers (and all five validators) meant one engine that
    failed to declare blocked a deploy to any other platform.
    """
    from opentide.platforms import plugins

    imported: list[str] = []
    original = plugins.PlatformLoader.import_engine

    class _BrokenEngine:
        @staticmethod
        def declare():
            raise RuntimeError("crowdstrike engine is misconfigured")

    def _record(module_path: str):
        imported.append(module_path)
        if "crowdstrike" in module_path:
            return _BrokenEngine
        return original(module_path)

    monkeypatch.setattr(plugins.PlatformLoader, "import_engine", staticmethod(_record))
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "sentinel",
        "--plan",
        "FULL",
        "--wide",
        "--skip-promotion",
    )
    payload = assert_json_ok(result)
    assert list(payload["payloads"]) == ["sentinel"]
    assert imported == ["opentide.platforms.sentinel.deployer"]
