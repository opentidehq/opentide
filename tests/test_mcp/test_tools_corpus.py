"""MCP tools against tide_corpus instead of a patched ``Opentide`` (#264)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS, CORPUS_TECHNIQUE, CORPUS_THREAT_UUID

from opentide.mcp_server import tools

MISSING_UUID = "00000000-0000-4000-8fff-0000000000ff"


def test_tool_search_returns_summary_list(tide_corpus_repo: Path) -> None:
    payload = tools.tool_search(CORPUS_RULE_UUIDS["sentinel"])
    assert isinstance(payload, list)
    assert [hit["uuid"] for hit in payload] == [CORPUS_RULE_UUIDS["sentinel"]]


def test_tool_coverage_matches_cli_info_coverage(tide_corpus_repo: Path) -> None:
    from opentide.cli.services.info import _technique_coverage

    mcp_rules = set(tools.tool_coverage(technique=CORPUS_TECHNIQUE)["rules"])
    cli_rules = set(_technique_coverage(CORPUS_TECHNIQUE)["rules"])
    assert mcp_rules == cli_rules


def test_tool_get_chaining_resolves_corpus_threat(tide_corpus_repo: Path) -> None:
    payload = tools.tool_get_chaining(CORPUS_THREAT_UUID)
    assert payload["found"] is True
    assert CORPUS_THREAT_UUID in payload["lineage"]["threats"]
    assert payload["lineage"]["objectives"]
    assert CORPUS_RULE_UUIDS["sentinel"] in payload["lineage"]["rules"]


@pytest.mark.parametrize("platform", sorted(CORPUS_RULE_UUIDS))
def test_tool_deployment_status_reads_real_configurations(
    tide_corpus_repo: Path, platform: str
) -> None:
    payload = tools.tool_deployment_status(CORPUS_RULE_UUIDS[platform])
    assert payload["found"] is True
    assert platform in payload["platforms"]


def test_tool_deploy_rule_dry_run_keeps_dry_run_action(tide_corpus_repo: Path) -> None:
    result = tools.tool_deploy_rule(CORPUS_RULE_UUIDS["sentinel"], "sentinel", dry_run=True)
    assert result["action"] == "dry-run"
    assert result["dry_run"] is True


def test_tool_deploy_rule_without_tenants_names_the_failure(tide_corpus_repo: Path) -> None:
    from opentide.models.rule import DetectionRule

    def fail_deploy(self: DetectionRule, platform: str, dry_run: bool = False) -> None:
        raise AssertionError(f"deploy engine called for {platform} dry_run={dry_run}")

    # The corpus Sentinel rule has a configuration block and no tenants.
    # A real deploy must stop with the CLI sentence and must not call the engine.
    import opentide.models.rule as rule_module

    original = rule_module.DetectionRule.deploy
    rule_module.DetectionRule.deploy = fail_deploy  # type: ignore[method-assign]
    try:
        result = tools.tool_deploy_rule(CORPUS_RULE_UUIDS["sentinel"], "sentinel", dry_run=False)
    finally:
        rule_module.DetectionRule.deploy = original  # type: ignore[method-assign]
    assert result["action"] == "error"
    assert result["status"] == "failed"
    assert "Cannot deploy:" in result["message"]
    assert "sentinel has no tenants configured" in result["message"]
    assert "TypeError" not in result["message"]


def test_tool_deploy_rule_reports_a_refused_rule_as_failed(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review issue 4: a refusal the deployer reports through the run flags is a failure.

    The Sentinel rule still carries a vendor id, so the deployer refuses it
    with external_id_in_rule before building the client.
    """
    from unittest.mock import MagicMock

    from tests.corpus_support import clear_runtime_caches

    uuid = CORPUS_RULE_UUIDS["sentinel"]
    path = next(
        p
        for p in (tide_corpus_repo / "objects" / "rules").glob("*.yaml")
        if uuid in p.read_text(encoding="utf-8")
    )
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace("  sentinel:\n", "  sentinel:\n    rule_id::contoso: 42\n", 1),
        encoding="utf-8",
    )
    clear_runtime_caches()
    monkeypatch.setattr(tools, "_missing_tenants", lambda *_: None)
    service = MagicMock(name="SentinelService")
    monkeypatch.setattr("opentide.platforms.sentinel.client.SentinelService", service)

    result = tools.tool_deploy_rule(uuid, "sentinel", dry_run=False)

    service.assert_not_called()
    assert result["status"] == "failed"
    assert result["action"] == "error"
    assert result["error"] == "deployment_failed"


def test_tool_deploy_rule_does_not_inherit_a_previous_failure(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.models.rule import DeploymentResult, DetectionRule

    def deployed(self: DetectionRule, platform: str, dry_run: bool = False) -> DeploymentResult:
        return DeploymentResult(platform=platform, uuids=[self.metadata.uuid], dry_run=dry_run)

    monkeypatch.setattr(DetectionRule, "deploy", deployed)
    monkeypatch.setattr(tools, "_missing_tenants", lambda *_: None)
    monkeypatch.setenv("DEPLOYMENT_ERROR_RAISED", "1")

    result = tools.tool_deploy_rule(CORPUS_RULE_UUIDS["sentinel"], "sentinel", dry_run=False)

    assert result["action"] == "deploy"
    assert result["status"] != "failed"


def test_tool_deploy_rule_unknown_platform_is_structured(tide_corpus_repo: Path) -> None:
    for dry_run in (True, False):
        result = tools.tool_deploy_rule(
            CORPUS_RULE_UUIDS["sentinel"], "not_a_platform", dry_run=dry_run
        )
        assert result["action"] == "error"
        assert result["status"] == "unknown_platform"
        assert result["message"] == "Unknown platform 'not_a_platform'"
        assert result["dry_run"] is dry_run


def test_tool_deployment_status_configuration_is_not_a_deploy(tide_corpus_repo: Path) -> None:
    payload = tools.tool_deployment_status(CORPUS_RULE_UUIDS["sentinel"])
    sentinel = payload["platforms"]["sentinel"]
    assert sentinel["deployed"] is False
    assert sentinel["rule_id"] is None


def test_platform_deployment_state_uses_recorded_external_ids() -> None:
    recorded = tools._platform_deployment_state({"tenants": ["contoso"]}, {"contoso": "12345"})
    assert recorded == {
        "deployed": True,
        "rule_id": "12345",
        "external_ids": {"contoso": "12345"},
        "tenants": ["contoso"],
    }
    two = tools._platform_deployment_state({}, {"a": "1", "b": "2"})
    assert two["deployed"] is True
    assert two["rule_id"] is None
    authoring = tools._platform_deployment_state({"enabled": True, "query": "SecurityEvent"})
    assert authoring["deployed"] is False
    assert authoring["rule_id"] is None
    assert authoring["external_ids"] == {}


def test_tool_deployment_status_reads_the_deployment_state_shard(tide_corpus_repo: Path) -> None:
    from opentide.states.deployment import record_external_id

    uuid = CORPUS_RULE_UUIDS["defender_for_endpoint"]
    record_external_id(uuid, "defender_for_endpoint", "contoso", 4242, tide_corpus_repo)
    payload = tools.tool_deployment_status(uuid)
    defender = payload["platforms"]["defender_for_endpoint"]
    assert defender["deployed"] is True
    assert defender["external_ids"] == {"contoso": "4242"}
    assert defender["rule_id"] == "4242"
    assert "state_error" not in payload


def test_tool_deployment_status_reports_a_broken_shard(tide_corpus_repo: Path) -> None:
    from opentide.states.deployment import shard_path

    uuid = CORPUS_RULE_UUIDS["defender_for_endpoint"]
    path = shard_path(uuid, tide_corpus_repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    payload = tools.tool_deployment_status(uuid)
    assert payload["found"] is True
    assert payload["state_error"]["code"] == "deployment_state_shape"


def test_tool_deployment_status_missing_rule(tide_corpus_repo: Path) -> None:
    payload = tools.tool_deployment_status(MISSING_UUID)
    assert payload["found"] is False


def test_tool_validate_rule_on_corpus_rule(tide_corpus_repo: Path) -> None:
    payload = tools.tool_validate_rule(CORPUS_RULE_UUIDS["sentinel"])
    assert payload["errors"] == []
    assert payload["valid"] is True


def test_tool_validate_rule_missing(tide_corpus_repo: Path) -> None:
    payload = tools.tool_validate_rule(MISSING_UUID)
    assert payload["valid"] is False
    assert payload["errors"]


def test_tool_validation_report_full_registry(tide_corpus_repo: Path) -> None:
    payload = tools.tool_validation_report()
    assert "issues" in payload
    assert payload["ok"] is True
