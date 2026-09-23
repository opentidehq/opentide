"""CLI E2E: deploy dry-run payloads."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pytest_console_scripts import ScriptRunner
from tests.corpus_support import (
    CORPUS_RULE_UUIDS,
    INERT_RULE_UUID,
    SUBFOLDER_RULE_UUIDS,
    add_unplanned_rules,
    classify_deploy_scope,
    real_rules_folder,
    write_rule_variant,
)
from tests.test_cli.conftest import LOCAL_SHELL_UNSET, assert_json_ok

from opentide.core.root import find_repo_root
from opentide.models.deployment_enums import StatusStrategy

pytestmark = pytest.mark.cli_e2e

SUBFOLDER_RULES_LEAD = (
    "rule file(s) in subfolders of objects/rules are not deployed (deploy reads only "
    "files directly in objects/rules; see https://github.com/OpenTideHQ/opentide/issues/312): "
)


def _mock_deployer(monkeypatch: pytest.MonkeyPatch, platform: str) -> MagicMock:
    """Stand in for *platform*'s engine; only the scoped loader is offered."""
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return {platform: deployer} if platform in set(platforms) else {}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    return deployer


def _log_events(stderr: str, event: str) -> list[dict[str, object]]:
    """The ``--json`` log records on stderr named *event*."""
    records = [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]
    return [record for record in records if record.get("event") == event]


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


@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
def test_deploy_dry_run_warns_about_rule_files_in_subfolders(
    invoke_cli,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    json_output: bool,
) -> None:
    """#300 follow-up: with the subfolder crash fixed, a nested rule was dropped silently."""
    for name in LOCAL_SHELL_UNSET:
        monkeypatch.delenv(name, raising=False)
    rules = real_rules_folder(tide_corpus_repo)
    nested_uuid = SUBFOLDER_RULE_UUIDS["team-a/rule-0101-subfolder.yaml"]
    write_rule_variant(rules, "team-a/rule-0101-subfolder.yaml", nested_uuid)
    deployer = _mock_deployer(monkeypatch, "sentinel")
    result = invoke_cli(
        "deploy",
        "--platform",
        "sentinel",
        "--dry-run",
        json_output=json_output,
        extra_env={"DEPLOYMENT_PLAN": ""},
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    deployer.deploy.assert_not_called()
    warning = f"1 {SUBFOLDER_RULES_LEAD}objects/rules/team-a/rule-0101-subfolder.yaml"
    if not json_output:
        assert "OK Deployment completed" in result.stdout
        stderr = " ".join(result.stderr.split())
        assert stderr.count(f"WARNING {warning}") == 1
        assert stderr.count("in subfolders of") == 1
        return
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed"
    assert payload["warnings"] == [warning]
    assert CORPUS_RULE_UUIDS["sentinel"] in payload["plan"]["sentinel"]
    assert nested_uuid not in payload["plan"]["sentinel"]
    assert [
        event["files"] for event in _log_events(result.stderr, "deploy_nested_rules_skipped")
    ] == [["objects/rules/team-a/rule-0101-subfolder.yaml"]]


@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
@pytest.mark.parametrize(
    ("argv", "fields", "message"),
    [
        pytest.param(
            ("--platform", "sentinel"),
            {"platform": "sentinel"},
            "No rules to deploy for this platform",
            id="one-platform",
        ),
        pytest.param((), {}, "No rules matched this deployment plan", id="every-platform"),
    ],
)
def test_deploy_dry_run_with_rules_only_in_subfolders_is_skipped_with_the_warning(
    invoke_cli,
    tide_corpus_repo: Path,
    refuse_deployment_engines: list[str],
    monkeypatch: pytest.MonkeyPatch,
    argv: tuple[str, ...],
    fields: dict[str, str],
    message: str,
    json_output: bool,
) -> None:
    for name in LOCAL_SHELL_UNSET:
        monkeypatch.delenv(name, raising=False)
    rules = real_rules_folder(tide_corpus_repo)
    (rules / "team-a").mkdir()
    for path in sorted(rules.glob("*.yaml")):
        path.rename(rules / "team-a" / path.name)
    result = invoke_cli(
        "deploy", *argv, "--dry-run", json_output=json_output, extra_env={"DEPLOYMENT_PLAN": ""}
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert refuse_deployment_engines == []
    warning = f"8 {SUBFOLDER_RULES_LEAD}" + ", ".join(
        [
            "objects/rules/team-a/rule-0001-sentinel-kql.yaml",
            "objects/rules/team-a/rule-0002-defender-kql.yaml",
            "objects/rules/team-a/rule-0003-splunk-spl.yaml",
            "objects/rules/team-a/rule-0004-sentinel-one-s1ql.yaml",
            "objects/rules/team-a/rule-0005-carbon-black-lucene.yaml",
            "+3 more",
        ]
    )
    if not json_output:
        assert f"SKIPPED {message}" in result.stdout
        assert " ".join(result.stderr.split()).count(f"WARNING {warning}") == 1
        return
    assert json.loads(result.stdout) == {
        **fields,
        "deployed": [],
        "dry_run": True,
        "plan": {},
        "payloads": {},
        "ok": True,
        "status": "skipped",
        "message": message,
        "warnings": [warning],
    }


@pytest.mark.parametrize("layout", ["plain", "symlinked"])
def test_full_dry_run_accounts_for_every_indexed_rule(
    invoke_cli,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    layout: str,
) -> None:
    """#312 guard: an indexed rule is planned, excluded by status, or named in a warning."""
    for name in LOCAL_SHELL_UNSET:
        monkeypatch.delenv(name, raising=False)
    if layout == "plain":
        real_rules_folder(tide_corpus_repo)
    add_unplanned_rules(tide_corpus_repo / "objects" / "rules")
    indexed = assert_json_ok(invoke_cli("info", "rules"))["rules"]
    payload = assert_json_ok(
        invoke_cli("deploy", "--dry-run", "--plan", "FULL", extra_env={"DEPLOYMENT_PLAN": ""})
    )
    scope = classify_deploy_scope(
        tide_corpus_repo,
        indexed,
        payload["plan"],
        payload.get("warnings", []),
        excluded=frozenset(
            {StatusStrategy.INERT, StatusStrategy.DISABLEMENT, StatusStrategy.DELETION}
        ),
    )
    assert scope["silent"] == set()
    assert set(CORPUS_RULE_UUIDS.values()) <= scope["planned"]
    assert scope["status"] == {INERT_RULE_UUID}
    assert scope["warned"] == set(SUBFOLDER_RULE_UUIDS.values())
