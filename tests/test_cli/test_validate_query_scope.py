"""``validate query --changed``, ``--file`` and ``--uuid`` narrow the rule files, not the tenants.

The generated pipelines sent every rule in the catalogue on every run: 45
minutes for a 467-rule Splunk catalogue. ``--strategy PREVIEW`` would cut
that too, but it also narrows the check to ``PREVIEW`` rules, so a merge
request that edits a ``PRODUCTION`` rule's query would merge it unchecked.
Without ``--strategy`` each rule is checked on the tenants a deploy sends it
to: here a ``STAGING`` rule on the ``PREVIEW`` tenant and a ``PRODUCTION``
rule on the ``RELEASE`` tenant.

The vendor SDK is replaced by stand-in modules, as in
``test_validate_query_tenants``: the real Sentinel validator runs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.corpus_support import (
    CORPUS_RULE_UUIDS,
    clear_runtime_caches,
    materialise_corpus,
    real_rules_folder,
    write_rule_variant,
)
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()

PREVIEW_WORKSPACE = "11111111-1111-4111-8111-111111111111"
RELEASE_WORKSPACE = "22222222-2222-4222-8222-222222222222"
SENTINEL_RULE = CORPUS_RULE_UUIDS["sentinel"]
CHANGED_RULE = "00000000-0000-4000-8003-000000000301"
ZERO_SHA = "0" * 40

_HIDDEN = (
    "CI",
    "CI_PROJECT_DIR",
    "CI_PIPELINE_SOURCE",
    "CI_COMMIT_SHA",
    "CI_COMMIT_BEFORE_SHA",
    "CI_MERGE_REQUEST_DIFF_BASE_SHA",
    "CI_MERGE_REQUEST_EVENT_TYPE",
    "GITHUB_ACTIONS",
    "GITHUB_EVENT_NAME",
    "GITHUB_WORKSPACE",
    "GITHUB_SHA",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "TF_BUILD",
    "BUILD_REASON",
    "BUILD_SOURCESDIRECTORY",
    "BUILD_SOURCEVERSION",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
    "DEPLOYMENT_PLAN",
)


def _tenant(name: str, strategy: str, workspace_id: str) -> str:
    return f"""
[[tenants]]
name = "{name}"
description = "{name} workspace"
strategies = ["{strategy}"]
[tenants.setup]
ssl = true
resource_group = "rg-{name.lower()}"
workspace_name = "{name.lower()}"
workspace_id = "{workspace_id}"
azure_tenant_id = "tenant-id"
azure_subscription_id = "subscription-id"
azure_client_id = "client-id"
azure_client_secret = "client-secret"
"""


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path) -> Path:
    """The corpus catalogue with a preview and a release Sentinel tenant, committed."""
    del git_home
    corpus = materialise_corpus(tmp_path / "corpus")
    repo = tmp_path / "repo"
    repo.mkdir()
    # Only the current layout: the legacy ``Objects/`` tree is the same folder
    # as ``objects/`` on a case-insensitive file system.
    shutil.copytree(corpus / ".opentide", repo / ".opentide")
    shutil.copytree(real_rules_folder(corpus), repo / "objects" / "rules")
    for family in ("objectives", "threats"):
        shutil.copytree(corpus / "objects" / family, repo / "objects" / family)
    config = repo / ".opentide/configurations/systems/sentinel.toml"
    config.write_text(
        config.read_text(encoding="utf-8")
        + _tenant("Preview", "PREVIEW", PREVIEW_WORKSPACE)
        + _tenant("Release", "RELEASE", RELEASE_WORKSPACE),
        encoding="utf-8",
    )
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "catalogue")
    for name in _HIDDEN:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    monkeypatch.chdir(repo)
    clear_runtime_caches()
    yield repo
    clear_runtime_caches()


@pytest.fixture
def azure_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Stand-in ``azure`` modules; the returned client records each query."""
    client = MagicMock(name="LogsQueryClient()")
    identity = types.ModuleType("azure.identity")
    identity.ClientSecretCredential = MagicMock(name="ClientSecretCredential")  # type: ignore[attr-defined]
    identity.CredentialUnavailableError = type("CredentialUnavailableError", (Exception,), {})  # type: ignore[attr-defined]
    query = types.ModuleType("azure.monitor.query")
    query.LogsQueryClient = MagicMock(name="LogsQueryClient", return_value=client)  # type: ignore[attr-defined]
    query.LogsQueryStatus = types.SimpleNamespace(SUCCESS="Success", PARTIAL="PartialError")  # type: ignore[attr-defined]
    client.query_workspace.return_value = types.SimpleNamespace(status="Success", tables=[])
    exceptions = types.ModuleType("azure.core.exceptions")
    for name in ("ClientAuthenticationError", "HttpResponseError", "ServiceRequestError"):
        setattr(exceptions, name, type(name, (Exception,), {}))
    modules = {
        "azure": types.ModuleType("azure"),
        "azure.identity": identity,
        "azure.monitor": types.ModuleType("azure.monitor"),
        "azure.monitor.query": query,
        "azure.core": types.ModuleType("azure.core"),
        "azure.core.exceptions": exceptions,
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    return client


def _change_a_production_rule(repo: Path) -> tuple[str, str]:
    """Commit a new ``PRODUCTION`` rule and return ``(base, head)``."""
    base = _git(repo, "rev-parse", "HEAD")
    write_rule_variant(
        repo / "objects" / "rules", "rule-0301-changed.yaml", CHANGED_RULE, status="PRODUCTION"
    )
    return base, _commit(repo, "a production rule")


def _ci_env(provider: str, repo: Path, base: str, head: str) -> dict[str, str]:
    if provider == "gitlab-merge-request":
        return {
            "CI": "true",
            "CI_PROJECT_DIR": str(repo),
            "CI_PIPELINE_SOURCE": "merge_request_event",
            "CI_MERGE_REQUEST_DIFF_BASE_SHA": base,
            "CI_COMMIT_SHA": head,
        }
    if provider == "gitlab-push":
        return {
            "CI": "true",
            "CI_PROJECT_DIR": str(repo),
            "CI_PIPELINE_SOURCE": "push",
            "CI_COMMIT_BEFORE_SHA": base,
            "CI_COMMIT_SHA": head,
        }
    if provider == "gitlab-manual":
        # No previous tip: a branch's first push, "Run pipeline", a schedule.
        return {
            "CI": "true",
            "CI_PROJECT_DIR": str(repo),
            "CI_PIPELINE_SOURCE": "web",
            "CI_COMMIT_BEFORE_SHA": ZERO_SHA,
            "CI_COMMIT_SHA": head,
        }
    if provider == "github-push":
        return {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_WORKSPACE": str(repo),
            "GITHUB_SHA": head,
        }
    if provider == "azure-push":
        return {
            "TF_BUILD": "True",
            "BUILD_REASON": "IndividualCI",
            "BUILD_SOURCESDIRECTORY": str(repo),
            "BUILD_SOURCEVERSION": head,
        }
    raise AssertionError(provider)


def _validate(*args: str, env: dict[str, str] | None = None) -> tuple[int, dict[str, object]]:
    result = runner.invoke(
        app,
        ["--json", "validate", "query", "--platform", "sentinel", "--live", *args],
        env=env,
    )
    return result.exit_code, json.loads(result.stdout)


def _queried_workspaces(client: MagicMock) -> list[str]:
    return [call.kwargs["workspace_id"] for call in client.query_workspace.call_args_list]


def test_without_a_scope_every_rule_is_checked(repo: Path, azure_client: MagicMock) -> None:
    _change_a_production_rule(repo)

    code, payload = _validate()

    assert code == 0, payload
    assert "scope" not in payload
    assert payload["strategies"] == ["PREVIEW", "RELEASE"]
    # rule-0001 and rule-0008 (STAGING) on the preview tenant, the new
    # PRODUCTION rule on the release tenant.
    assert payload["queries_per_tenant"] == {"Preview": 2, "Release": 1}


@pytest.mark.parametrize(
    "provider",
    ["gitlab-merge-request", "gitlab-push", "gitlab-manual", "github-push", "azure-push"],
)
def test_changed_checks_only_the_rules_the_run_changed_where_they_deploy(
    repo: Path, azure_client: MagicMock, provider: str
) -> None:
    base, head = _change_a_production_rule(repo)

    code, payload = _validate("--changed", env=_ci_env(provider, repo, base, head))

    assert code == 0, payload
    assert payload["status"] == "passed"
    assert payload["scope"] == "changed"
    # No --strategy: the changed PRODUCTION rule is checked on the release tenant,
    # including on a merge request, which --strategy PREVIEW would have skipped.
    assert payload["strategies"] == ["PREVIEW", "RELEASE"]
    assert payload["queries_per_tenant"] == {"Release": 1}
    assert _queried_workspaces(azure_client) == [RELEASE_WORKSPACE]


def test_changed_with_no_changed_rule_skips_without_a_query(
    repo: Path, azure_client: MagicMock
) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text("no rule changed\n", encoding="utf-8")
    head = _commit(repo, "readme")

    code, payload = _validate("--changed", env=_ci_env("gitlab-merge-request", repo, base, head))

    assert code == 0, payload
    assert payload["status"] == "skipped"
    assert payload["scope"] == "changed"
    assert payload["message"] == (
        "No changed rule for this platform has a status that maps to the run's strategies"
    )
    azure_client.query_workspace.assert_not_called()


def test_changed_outside_ci_checks_the_last_commit(repo: Path, azure_client: MagicMock) -> None:
    """Outside CI ``--changed`` reads the local checkout's last commit (``HEAD^1..HEAD``)."""
    _change_a_production_rule(repo)

    code, payload = _validate("--changed")

    assert code == 0, payload
    assert payload["status"] == "passed"
    assert payload["scope"] == "changed"
    assert payload["queries_per_tenant"] == {"Release": 1}
    assert _queried_workspaces(azure_client) == [RELEASE_WORKSPACE]


def test_changed_outside_ci_reads_only_the_last_commit(repo: Path, azure_client: MagicMock) -> None:
    """A rule changed by an earlier commit is not in the last commit's diff."""
    _change_a_production_rule(repo)
    (repo / "README.md").write_text("no rule changed\n", encoding="utf-8")
    _commit(repo, "readme")

    code, payload = _validate("--changed")

    assert code == 0, payload
    assert payload["status"] == "skipped"
    assert payload["scope"] == "changed"
    azure_client.query_workspace.assert_not_called()


def test_changed_outside_a_git_checkout_names_the_missing_checkout(
    repo: Path, azure_client: MagicMock
) -> None:
    shutil.rmtree(repo / ".git")

    code, payload = _validate("--changed")

    assert code == 1, payload
    assert payload["status"] == "failed"
    assert "--changed needs a git checkout" in str(payload["message"])
    azure_client.query_workspace.assert_not_called()


def test_changed_cannot_be_combined_with_file(repo: Path, azure_client: MagicMock) -> None:
    code, payload = _validate("--changed", "--file", "rule-0008-staging-promote.yaml")

    assert code == 2, payload
    assert payload["message"] == "--changed cannot be combined with --file or --uuid"
    azure_client.query_workspace.assert_not_called()


@pytest.mark.parametrize(
    ("args", "per_tenant"),
    [
        (("--file", "rule-0008-staging-promote.yaml"), {"Preview": 1}),
        (("--file", "objects/rules/rule-0008-staging-promote.yaml"), {"Preview": 1}),
        (("--uuid", SENTINEL_RULE), {"Preview": 1}),
        (("--uuid", SENTINEL_RULE.upper()), {"Preview": 1}),
        (("--file", "rule-0008-staging-promote.yaml", "--uuid", SENTINEL_RULE), {"Preview": 2}),
        (("--uuid", CHANGED_RULE), {"Release": 1}),
        (("--uuid", SENTINEL_RULE, "--uuid", CHANGED_RULE), {"Preview": 1, "Release": 1}),
    ],
    ids=[
        "file-name",
        "file-path",
        "uuid",
        "uuid-uppercase",
        "file-and-uuid",
        "release-rule",
        "preview-and-release-rules",
    ],
)
def test_file_and_uuid_check_only_the_selected_rules(
    repo: Path, azure_client: MagicMock, args: tuple[str, ...], per_tenant: dict[str, int]
) -> None:
    _change_a_production_rule(repo)

    code, payload = _validate(*args)

    assert code == 0, payload
    assert payload["scope"] == "selected"
    assert payload["strategies"] == ["PREVIEW", "RELEASE"]
    assert payload["queries_per_tenant"] == per_tenant


def test_an_explicit_strategy_narrows_the_selected_rules(
    repo: Path, azure_client: MagicMock
) -> None:
    _change_a_production_rule(repo)

    code, payload = _validate(
        "--strategy", "release", "--uuid", SENTINEL_RULE, "--uuid", CHANGED_RULE
    )

    assert code == 0, payload
    assert payload["strategies"] == ["RELEASE"]
    assert payload["queries_per_tenant"] == {"Release": 1}
    assert _queried_workspaces(azure_client) == [RELEASE_WORKSPACE]


def test_a_target_that_selects_no_rule_fails_before_any_query(
    repo: Path, azure_client: MagicMock
) -> None:
    missing = "00000000-0000-4000-8003-000000000999"

    code, payload = _validate(
        "--file", "rule-0008-staging-promote.yaml", "--file", "nope.yaml", "--uuid", missing
    )

    assert code == 1, payload
    assert payload["status"] == "failed"
    assert payload["unmatched"] == ["nope.yaml", missing]
    assert "nope.yaml" in str(payload["message"])
    azure_client.query_workspace.assert_not_called()


def test_a_selected_rule_with_no_block_for_the_platform_is_skipped(
    repo: Path, azure_client: MagicMock
) -> None:
    code, payload = _validate("--uuid", CORPUS_RULE_UUIDS["splunk"])

    assert code == 0, payload
    assert payload["status"] == "skipped"
    assert payload["scope"] == "selected"
    azure_client.query_workspace.assert_not_called()


def test_changed_on_a_fork_pull_request_diffs_from_the_merge_ref(
    repo: Path, azure_client: MagicMock, tmp_path: Path
) -> None:
    """A fork's head branch is not on origin; the pull request merge ref has both sides."""
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", str(origin))
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "main")
    _git(repo, "checkout", "-q", "-b", "fork-feature")
    _change_a_production_rule(repo)
    # The shape of refs/pull/<n>/merge that actions/checkout checks out.
    _git(repo, "checkout", "-q", "--detach", "main")
    _git(repo, "merge", "--no-ff", "-q", "-m", "merge fork", "fork-feature")
    merge = _git(repo, "rev-parse", "HEAD")
    env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_WORKSPACE": str(repo),
        "GITHUB_HEAD_REF": "fork-feature",
        "GITHUB_BASE_REF": "main",
        "GITHUB_SHA": merge,
    }

    code, payload = _validate("--changed", env=env)

    assert code == 0, payload
    assert payload["scope"] == "changed"
    assert payload["queries_per_tenant"] == {"Release": 1}


def test_the_generated_gate_checks_the_changed_rules_where_they_deploy(
    repo: Path, azure_client: MagicMock
) -> None:
    from opentide.ci.stages import query_validation_command

    base, head = _change_a_production_rule(repo)
    command = query_validation_command("sentinel")
    assert command == "opentide validate query --platform sentinel --live --changed"
    argv = command.split()[1:]

    result = runner.invoke(
        app, ["--json", *argv], env=_ci_env("gitlab-merge-request", repo, base, head)
    )
    payload = json.loads(result.stdout)

    assert result.exit_code == 0, payload
    assert payload["strategies"] == ["PREVIEW", "RELEASE"]
    assert payload["queries_per_tenant"] == {"Release": 1}


@pytest.mark.parametrize(
    ("plan", "replacement"),
    [
        ("STAGING", "--strategy PREVIEW"),
        ("PRODUCTION", "--strategy RELEASE"),
        ("FULL", "--strategy PREVIEW --strategy RELEASE --all"),
    ],
)
def test_an_inherited_deployment_plan_fails_the_generated_gate(
    repo: Path, azure_client: MagicMock, plan: str, replacement: str
) -> None:
    """``DEPLOYMENT_PLAN`` was removed in 0.17.0: a pipeline still setting it fails loudly."""
    from opentide.ci.stages import query_validation_command
    from opentide.models.deployment_enums import removed_plan_message

    base, head = _change_a_production_rule(repo)
    env = {**_ci_env("gitlab-merge-request", repo, base, head), "DEPLOYMENT_PLAN": plan}
    argv = query_validation_command("sentinel").split()[1:]

    result = runner.invoke(app, ["--json", *argv], env=env)
    payload = json.loads(result.stdout)

    assert result.exit_code == 2, payload
    assert payload["status"] == "failed"
    assert payload["message"] == removed_plan_message(plan)
    assert "DEPLOYMENT_PLAN was removed in 0.17.0" in str(payload["message"])
    assert f"Use {replacement}." in str(payload["message"])
    azure_client.query_workspace.assert_not_called()
