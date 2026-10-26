"""CLI E2E: deploy dry-run payloads."""

from __future__ import annotations

import json
import os
import subprocess
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
from tests.test_cli.conftest import LOCAL_SHELL_UNSET, assert_json_ok, without_envelope
from tests.test_cli.e2e.helpers import EVERY_RULE, uncomment_tenants

from opentide.core.root import find_repo_root
from opentide.models.deployment_enums import StatusStrategy

pytestmark = pytest.mark.cli_e2e

SUBFOLDER_RULES_LEAD = (
    "rule file(s) in subfolders of objects/rules are not deployed (deploy reads only "
    "files directly in objects/rules; see https://github.com/opentidehq/opentide/issues/312): "
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
        *EVERY_RULE,
        "--wide",
        "--skip-promotion",
    )
    payload = assert_json_ok(result)
    assert payload["dry_run"] is True
    assert payload["strategies"] == ["PREVIEW", "RELEASE"]
    expected_uuid = corpus_rule_uuids[platform]
    assert expected_uuid in payload["plan"][platform]
    previews = payload["payloads"][platform]
    assert any(item["uuid"] == expected_uuid for item in previews)
    assert previews[0]["api_request"]
    deployer.deploy.assert_not_called()


def test_deploy_dry_run_without_strategy_or_wide_asks_for_a_strategy(
    invoke_cli,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Local CLI: a deploy naming no strategy is a usage error, not a traceback (#164)."""
    from opentide.cli.services.deploy import STRATEGY_REQUIRED

    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    deployer = _mock_deployer(monkeypatch, "sentinel")
    result = invoke_cli("deploy", "--dry-run", "--platform", "sentinel", "--skip-promotion")
    assert result.exit_code == 2, result.stdout + result.stderr
    assert "Traceback" not in result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert payload["message"] == STRATEGY_REQUIRED
    deployer.deploy.assert_not_called()


@pytest.mark.parametrize(
    ("argv", "env", "replacement"),
    [
        pytest.param(
            ("--plan", "FULL"), {}, "--strategy PREVIEW --strategy RELEASE --all", id="flag"
        ),
        pytest.param(("--plan", "STAGING"), {}, "--strategy PREVIEW", id="flag-staging"),
        pytest.param(
            ("--strategy", "PREVIEW"),
            {"DEPLOYMENT_PLAN": "PRODUCTION"},
            "--strategy RELEASE",
            id="environment",
        ),
    ],
)
def test_deploy_refuses_the_removed_deployment_plan(
    invoke_cli,
    refuse_deployment_engines: list[str],
    argv: tuple[str, ...],
    env: dict[str, str],
    replacement: str,
) -> None:
    """0.17.0 hard-removed ``--plan`` and ``DEPLOYMENT_PLAN``: both name their replacement."""
    result = invoke_cli("deploy", "--dry-run", *argv, extra_env=env)
    output = result.stdout + result.stderr
    assert result.exit_code == 2, output
    assert "Traceback" not in output
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert "removed in 0.17.0" in payload["message"]
    assert f"Use {replacement}." in payload["message"]
    if env:
        assert "Unset DEPLOYMENT_PLAN" in payload["message"]
    assert refuse_deployment_engines == []


@pytest.mark.parametrize(
    ("value", "hint"),
    [
        pytest.param("PRODUCTION", "PRODUCTION was a deployment plan", id="old-plan"),
        pytest.param("UNIVERSAL", "UNIVERSAL", id="status-strategy"),
        pytest.param("BOGUS", "Use PREVIEW or RELEASE", id="unknown"),
    ],
)
def test_deploy_refuses_a_strategy_it_cannot_run(
    invoke_cli, refuse_deployment_engines: list[str], value: str, hint: str
) -> None:
    result = invoke_cli("deploy", "--dry-run", "--strategy", value, "--all")
    output = result.stdout + result.stderr
    assert result.exit_code == 2, output
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert f"--strategy '{value}' is not a deployable strategy" in payload["message"]
    assert hint in payload["message"]
    assert refuse_deployment_engines == []


def test_deploy_strategy_is_case_insensitive_and_accepts_a_list(
    invoke_cli, corpus_rule_uuids, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_deployer(monkeypatch, "sentinel")
    result = invoke_cli(
        "deploy", "--dry-run", "--platform", "sentinel", "--strategy", "release,preview", "--all"
    )
    payload = assert_json_ok(result)
    assert payload["strategies"] == ["PREVIEW", "RELEASE"]
    assert corpus_rule_uuids["sentinel"] in payload["plan"]["sentinel"]


def test_deploy_dry_run_preview_without_wide_does_not_traceback(
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
        "--strategy",
        "PREVIEW",
        "--all",
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
        *EVERY_RULE,
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


def test_deploy_dry_run_fails_when_a_sentinel_rule_does_not_compile(
    invoke_cli,
    tide_corpus_repo: Path,
    corpus_rule_uuids,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compile error is a failed dry-run naming the rule, not a config-block preview (#545)."""
    _mock_deployer(monkeypatch, "sentinel")
    rule_file = tide_corpus_repo / "objects/rules/rule-0001-sentinel-kql.yaml"
    rule_file.write_text(
        rule_file.read_text(encoding="utf-8").replace("frequency: PT1H", "frequency: hourly"),
        encoding="utf-8",
    )
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "sentinel",
        *EVERY_RULE,
        "--wide",
        "--skip-promotion",
        # Click restores keys it was given, so the flag the preview raises
        # does not leak into later in-process tests.
        extra_env={"DEPLOYMENT_ERROR_RAISED": ""},
    )
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    preview = next(
        item
        for item in payload["payloads"]["sentinel"]
        if item["uuid"] == corpus_rule_uuids["sentinel"]
    )
    assert preview["status"] == "failed"
    assert "hourly" in preview["error"]
    assert preview["api_request"] is None
    # One diagnostic, said once: the log carries it only under --debug.
    (diagnostic,) = payload["diagnostics"]
    assert diagnostic["path"].endswith("/rule-0001-sentinel-kql.yaml")
    assert not Path(diagnostic["path"]).is_absolute()
    assert diagnostic["code"] == "compile_invalid_rule"
    assert "TideRuleDataModelErrors" not in diagnostic["message"]
    assert payload["failure"]["message"] == "1 rule would fail to deploy"
    assert not _log_events(result.stderr, "sentinel_preview_compile_failed")

    human = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "sentinel",
        *EVERY_RULE,
        "--wide",
        "--skip-promotion",
        json_output=False,
        extra_env={"DEPLOYMENT_ERROR_RAISED": "", "OPENTIDE_OUTPUT": "plain"},
    )
    assert human.exit_code == 1
    assert "error[compile_invalid_rule]: Duration 'hourly'" in human.stderr
    assert f"  --> {diagnostic['path']}" in human.stderr
    (tally,) = [line for line in human.stdout.splitlines() if line.startswith("Plan: ")]
    assert len(tally) <= 100
    assert "error: Plan" not in human.stdout + human.stderr


def test_deploy_loads_only_the_requested_engine(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No DeployTide mock: the real loader must not build every platform's engine.

    Loading all eight deployers (and all six validators) meant one engine that
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
        *EVERY_RULE,
        "--wide",
        "--skip-promotion",
    )
    payload = assert_json_ok(result)
    assert list(payload["payloads"]) == ["sentinel"]
    assert imported == ["opentide.platforms.sentinel.deployer"]


def _disable_splunk(repo: Path) -> None:
    config = repo / ".opentide/configurations/systems/splunk.toml"
    text = config.read_text(encoding="utf-8")
    assert "[tide]\nenabled = true\n" in text
    config.write_text(
        text.replace("[tide]\nenabled = true\n", "[tide]\nenabled = false\n"), encoding="utf-8"
    )


@pytest.mark.parametrize("wide", [False, True], ids=["status", "wide"])
def test_deploy_to_a_disabled_platform_loads_no_engine(
    invoke_cli, tide_corpus_repo: Path, refuse_deployment_engines: list[str], wide: bool
) -> None:
    """#414: the corpus Splunk rule says ``enabled: true``; the workspace does not."""
    _disable_splunk(tide_corpus_repo)
    argv = ["deploy", "--platform", "splunk", *EVERY_RULE]
    result = invoke_cli(*argv, *(["--wide"] if wide else []))
    payload = assert_json_ok(result)
    assert payload["status"] == "skipped"
    assert payload["message"] == "No rules to deploy for this platform"
    assert payload["plan"] == {}
    assert refuse_deployment_engines == []
    (event,) = _log_events(result.stderr, "system_disabled_for_deploy")
    assert event["advice"] == "enable it with 'opentide setup platforms --splunk'"


def test_wide_dry_run_never_builds_a_disabled_platform_engine(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#414: the other platforms still plan and load; Splunk is neither planned nor built."""
    from opentide.platforms import plugins

    _disable_splunk(tide_corpus_repo)
    imported: list[str] = []
    original = plugins.PlatformLoader.import_engine

    def _record(module_path: str):
        imported.append(module_path)
        return original(module_path)

    monkeypatch.setattr(plugins.PlatformLoader, "import_engine", staticmethod(_record))
    result = invoke_cli("deploy", "--dry-run", *EVERY_RULE, "--wide", "--skip-promotion")
    payload = assert_json_ok(result)
    assert "splunk" not in payload["plan"]
    assert "splunk" not in payload["payloads"]
    assert "sentinel" in payload["plan"]
    assert "opentide.platforms.sentinel.deployer" in imported
    assert not [path for path in imported if "splunk" in path]


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
        *EVERY_RULE,
        repo=workspace,
        json_output=json_output,
    )
    output = result.stdout + result.stderr
    assert result.exit_code == 0, output
    assert "Errno" not in output
    assert "No such file or directory" not in output
    assert refuse_deployment_engines == []
    if not json_output:
        assert "Skipped: No rules to deploy for this platform" in result.stdout
        return
    payload = json.loads(result.stdout)
    assert without_envelope(payload) == {
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
    argv = ["opentide", "deploy", "--platform", "sentinel", "--dry-run", *EVERY_RULE]

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
    # The corpus ships #[[tenants]] commented out. A tenantless platform adds its
    # own warning (#314); this test is about the nested-rule warning alone.
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/systems/sentinel.toml")
    deployer = _mock_deployer(monkeypatch, "sentinel")
    result = invoke_cli(
        "deploy",
        "--platform",
        "sentinel",
        "--dry-run",
        *EVERY_RULE,
        json_output=json_output,
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    deployer.deploy.assert_not_called()
    warning = f"1 {SUBFOLDER_RULES_LEAD}objects/rules/team-a/rule-0101-subfolder.yaml"
    if not json_output:
        assert "Plan: " in result.stdout and "1 platform" in result.stdout
        stderr = " ".join(result.stderr.split())
        assert stderr.count(f"warning: {warning}") == 1
        assert stderr.count("in subfolders of") == 1
        return
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed"
    assert payload["warnings"] == [warning]
    assert CORPUS_RULE_UUIDS["sentinel"] in payload["plan"]["sentinel"]
    assert nested_uuid not in payload["plan"]["sentinel"]
    # Reported once, in `warnings`: the log event is INFO, below --json's WARNING level.
    assert _log_events(result.stderr, "deploy_nested_rules_skipped") == []


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
        pytest.param(
            (),
            {},
            "No rule this run read has a status that maps to its strategies",
            id="every-platform",
        ),
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
    result = invoke_cli("deploy", *argv, "--dry-run", *EVERY_RULE, json_output=json_output)
    assert result.exit_code == 0, result.stdout + result.stderr
    assert refuse_deployment_engines == []
    warning = f"9 {SUBFOLDER_RULES_LEAD}" + ", ".join(
        [
            "objects/rules/team-a/rule-0001-sentinel-kql.yaml",
            "objects/rules/team-a/rule-0002-defender-kql.yaml",
            "objects/rules/team-a/rule-0003-splunk-spl.yaml",
            "objects/rules/team-a/rule-0004-sentinel-one-s1ql.yaml",
            "objects/rules/team-a/rule-0005-carbon-black-lucene.yaml",
            "+4 more",
        ]
    )
    if not json_output:
        assert f"Skipped: {message}" in result.stdout
        assert " ".join(result.stderr.split()).count(f"warning: {warning}") == 1
        return
    assert without_envelope(json.loads(result.stdout)) == {
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
    payload = assert_json_ok(invoke_cli("deploy", "--dry-run", *EVERY_RULE))
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


def _sentinel_tenants(repo: Path, *tenants: tuple[str, str]) -> None:
    """Replace the corpus Sentinel tenant example with *tenants* ``(name, keys)``."""
    config = repo / ".opentide/configurations/systems/sentinel.toml"
    template, example = config.read_text(encoding="utf-8").split("#[[tenants]]")
    setup = example[example.index("#[tenants.setup]") :].replace("#", "")
    blocks = [f'[[tenants]]\nname = "{name}"\n{keys}\n{setup}' for name, keys in tenants]
    config.write_text(template + "\n".join(blocks), encoding="utf-8")


def _rule_for_tenants(rules: Path, relative: str, uuid: str, status: str, tenants=()) -> None:
    path = write_rule_variant(rules, relative, uuid, status=status)
    if tenants:
        listed = "".join(f"      - {name}\n" for name in tenants)
        text = path.read_text(encoding="utf-8")
        text = text.replace("    status: STAGING\n", f"    status: {status}\n")
        text = text.replace("    enabled: true\n", f"    enabled: true\n    tenants:\n{listed}", 1)
        path.write_text(text, encoding="utf-8")


#: A Sentinel rule in each strategy a run deploys; the corpus rule is STAGING (PREVIEW).
RELEASE_RULE = "00000000-0000-4000-8003-000000000201"
MANUAL_RULE = "00000000-0000-4000-8003-000000000202"


@pytest.mark.parametrize(
    ("strategies", "expected"),
    [
        pytest.param(
            ("PREVIEW",),
            {"preview-only": [CORPUS_RULE_UUIDS["sentinel"]], "manual": [MANUAL_RULE]},
            id="preview",
        ),
        pytest.param(("RELEASE",), {"release-only": [RELEASE_RULE]}, id="release"),
        pytest.param(
            ("PREVIEW", "RELEASE"),
            {
                "preview-only": [CORPUS_RULE_UUIDS["sentinel"]],
                "release-only": [RELEASE_RULE],
                "manual": [MANUAL_RULE],
            },
            id="both",
        ),
    ],
)
def test_dry_run_reports_which_tenants_each_strategy_reaches(
    invoke_cli,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    strategies: tuple[str, ...],
    expected: dict[str, list[str]],
) -> None:
    """Tenant ``strategies`` filter by the rule's status strategy; ``manual`` needs a listing."""
    rules = real_rules_folder(tide_corpus_repo)
    for path in rules.glob("*.yaml"):
        if path.name != "rule-0001-sentinel-kql.yaml":
            path.unlink()
    _rule_for_tenants(rules, "rule-0201-release.yaml", RELEASE_RULE, "PRODUCTION")
    _rule_for_tenants(rules, "rule-0202-manual.yaml", MANUAL_RULE, "STAGING", tenants=["manual"])
    _sentinel_tenants(
        tide_corpus_repo,
        ("preview-only", 'strategies = ["PREVIEW"]'),
        ("release-only", 'strategies = ["RELEASE"]'),
        ("manual", "manual = true"),
    )
    _mock_deployer(monkeypatch, "sentinel")
    flags = [arg for strategy in strategies for arg in ("--strategy", strategy)]
    result = invoke_cli(
        "deploy", "--dry-run", "--platform", "sentinel", *flags, "--all", "--skip-promotion"
    )
    payload = assert_json_ok(result)
    assert payload["strategies"] == list(strategies)
    assert {tenant: sorted(uuids) for tenant, uuids in payload["tenants"]["sentinel"].items()} == {
        tenant: sorted(uuids) for tenant, uuids in expected.items()
    }
    assert sorted(payload["plan"]["sentinel"]) == sorted(
        {uuid for uuids in expected.values() for uuid in uuids}
    )


def test_a_tenant_with_the_removed_deployment_key_names_its_replacement(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """0.17.0 removed the tenant key ``deployment``; loading it says what replaces it."""
    _sentinel_tenants(tide_corpus_repo, ("legacy", 'deployment = "STAGING"'))
    replacement = (
        "sentinel tenant 'legacy': the tenant key 'deployment' was removed in 0.17.0. "
        "A tenant now lists the status strategies it accepts. "
        "Replace deployment = 'STAGING' with strategies = [\"PREVIEW\"]."
    )
    live = invoke_cli("validate", "query", "--platform", "sentinel", "--live")
    assert live.exit_code == 1, live.stdout + live.stderr
    payload = json.loads(live.stdout)
    assert payload["status"] == "failed"
    assert payload["message"] == replacement

    deployer = _mock_deployer(monkeypatch, "sentinel")
    for dry_run in (("--dry-run",), ()):
        result = invoke_cli(
            "deploy", *dry_run, "--platform", "sentinel", *EVERY_RULE, "--skip-promotion"
        )
        output = result.stdout + result.stderr
        assert "Traceback" not in output
        assert result.exit_code == 1, output
        payload = json.loads(result.stdout)
        assert payload["status"] == "failed"
        assert payload["message"] == replacement
        assert payload["deployed"] == []
    deployer.deploy.assert_not_called()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_local_deploy_reads_the_files_the_last_commit_changed(
    invoke_cli,
    git_home: Path,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outside CI and without ``--all``, a deploy reads ``HEAD^1..HEAD`` of the checkout."""
    for name in LOCAL_SHELL_UNSET:
        monkeypatch.delenv(name, raising=False)
    rules = real_rules_folder(tide_corpus_repo)
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/systems/sentinel.toml")
    _git(tide_corpus_repo, "init", "-q", "-b", "main")
    _git(tide_corpus_repo, "add", "-A")
    _git(tide_corpus_repo, "commit", "-q", "-m", "corpus")
    changed = rules / "rule-0001-sentinel-kql.yaml"
    changed.write_text(
        changed.read_text(encoding="utf-8").replace("take 1", "take 2"), encoding="utf-8"
    )
    _git(tide_corpus_repo, "commit", "-q", "-am", "tune the sentinel rule")
    # An uncommitted change is not part of the last commit.
    other = rules / "rule-0002-defender-kql.yaml"
    other.write_text(other.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    _mock_deployer(monkeypatch, "sentinel")

    payload = assert_json_ok(invoke_cli("deploy", "--dry-run", "--strategy", "PREVIEW"))
    assert payload["plan"] == {"sentinel": [CORPUS_RULE_UUIDS["sentinel"]]}
    assert payload["strategies"] == ["PREVIEW"]

    # The same commit read by a RELEASE run: a STAGING rule maps to PREVIEW.
    skipped = assert_json_ok(invoke_cli("deploy", "--dry-run", "--strategy", "RELEASE"))
    assert skipped["status"] == "skipped"
    assert skipped["message"] == "No rule this run read has a status that maps to its strategies"


def test_local_deploy_without_a_checkout_points_at_all(
    invoke_cli,
    tide_corpus_repo: Path,
    refuse_deployment_engines: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in LOCAL_SHELL_UNSET:
        monkeypatch.delenv(name, raising=False)
    result = invoke_cli("deploy", "--dry-run", "--strategy", "PREVIEW")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert "git checkout" in payload["message"]
    assert "--all" in payload["message"]
    assert refuse_deployment_engines == []
