"""CLI E2E: deploy dry-run payloads."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pytest_console_scripts import ScriptRunner
from tests.test_cli.conftest import LOCAL_SHELL_UNSET, assert_json_ok

from opentide.core.root import find_repo_root

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
    assert payload["deployed"] == ["sentinel"]
    assert imported == ["opentide.platforms.sentinel.deployer"]


@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
def test_deploy_dry_run_without_rules_folder_reports_no_rules(
    invoke_cli,
    refuse_deployment_engines: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    json_output: bool,
) -> None:
    """Issue #300: no ``objects/rules`` exited 1 with ``FATAL: [Errno 2] ...``."""
    for name in LOCAL_SHELL_UNSET:
        monkeypatch.delenv(name, raising=False)
    workspace = tmp_path / "empty"
    workspace.mkdir()
    result = invoke_cli(
        "deploy",
        "--platform",
        "sentinel",
        "--dry-run",
        repo=workspace,
        json_output=json_output,
        extra_env={"DEPLOYMENT_PLAN": ""},
    )
    output = result.stdout + result.stderr
    assert result.exit_code == 0, output
    assert "Errno" not in output
    assert "No such file or directory" not in output
    assert refuse_deployment_engines == []
    if not json_output:
        assert "SKIPPED No rules to deploy for this platform" in result.stdout
        return
    payload = json.loads(result.stdout)
    assert payload == {
        "platform": "sentinel",
        "deployed": [],
        "dry_run": True,
        "plan": {},
        "payloads": {},
        "ok": True,
        "status": "skipped",
        "message": "No rules to deploy for this platform",
    }


@pytest.mark.cli_smoke
@pytest.mark.script_launch_mode("subprocess")
def test_deploy_dry_run_in_an_empty_directory_on_console_script(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """The #300 report verbatim: cwd is the workspace, no ``.git``, no env root."""
    workspace = tmp_path / "empty"
    workspace.mkdir()
    assert find_repo_root(workspace) == workspace.resolve(), "a parent directory is a git tree"
    env = {k: v for k, v in os.environ.items() if k not in LOCAL_SHELL_UNSET}
    argv = ["opentide", "deploy", "--platform", "sentinel", "--dry-run"]

    human = script_runner.run(argv, cwd=workspace, env=env, print_result=False)
    assert human.returncode == 0, human.stdout + human.stderr
    assert "Errno" not in human.stdout + human.stderr
    assert "No rules to deploy for this platform" in human.stdout

    machine = script_runner.run(
        [argv[0], "--json", *argv[1:]], cwd=workspace, env=env, print_result=False
    )
    assert machine.returncode == 0, machine.stdout + machine.stderr
    assert "Errno" not in machine.stdout + machine.stderr
    payload = json.loads(machine.stdout)
    assert payload["status"] == "skipped"
    assert payload["dry_run"] is True
    assert payload["plan"] == {}
