"""Live query validation reaches every tenant a rule can, and never passes on nothing (#547).

``validate query --live`` with no plan runs the ``FULL`` plan. Tenant
resolution used to accept only ``ALWAYS``, ``MANUAL`` and plan-equal tenants,
so the usual ``STAGING`` + ``PRODUCTION`` layout resolved no tenant and the
command reported ``passed`` without sending a query.

The vendor SDK is replaced by stand-in modules: the real Sentinel validator
runs, and the only fake is the Azure client it talks to.
"""

from __future__ import annotations

import json
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.corpus_support import clear_runtime_caches, materialise_corpus
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()

STAGING_WORKSPACE = "11111111-1111-4111-8111-111111111111"
PRODUCTION_WORKSPACE = "22222222-2222-4222-8222-222222222222"
SENTINEL_RULE = "00000000-0000-4000-8003-000000000001"


def _tenant(name: str, deployment: str, workspace_id: str) -> str:
    return f"""
[[tenants]]
name = "{name}"
description = "{name} workspace"
deployment = "{deployment}"
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


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    repo = materialise_corpus(tmp_path / "corpus")
    for name in ("CI", "GITHUB_ACTIONS", "TF_BUILD", "DEPLOYMENT_PLAN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    clear_runtime_caches()
    yield repo
    clear_runtime_caches()


def _configure(repo: Path, *tenants: str) -> None:
    config = repo / ".opentide/configurations/systems/sentinel.toml"
    config.write_text(config.read_text(encoding="utf-8") + "".join(tenants), encoding="utf-8")


def _restrict_rule(repo: Path, *tenants: str) -> None:
    """Name the tenants the corpus Sentinel rule targets."""
    path = repo / "Objects/Detection Rules/rule-0001-sentinel-kql.yaml"
    listed = "".join(f"      - {name}\n" for name in tenants)
    text = path.read_text(encoding="utf-8").replace(
        "    status: STAGING\n", f"    status: STAGING\n    tenants:\n{listed}", 1
    )
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def azure_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Stand-in ``azure`` modules; the returned client records each query."""
    client = MagicMock(name="LogsQueryClient()")
    identity = types.ModuleType("azure.identity")
    identity.ClientSecretCredential = MagicMock(name="ClientSecretCredential")  # type: ignore[attr-defined]
    identity.CredentialUnavailableError = type("CredentialUnavailableError", (Exception,), {})  # type: ignore[attr-defined]
    query = types.ModuleType("azure.monitor.query")
    query.LogsQueryClient = MagicMock(name="LogsQueryClient", return_value=client)  # type: ignore[attr-defined]
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


def _queried_workspaces(client: MagicMock) -> list[str]:
    return [call.kwargs["workspace_id"] for call in client.query_workspace.call_args_list]


def _validate(*args: str) -> tuple[int, dict[str, object]]:
    result = runner.invoke(
        app, ["--json", "validate", "query", "--platform", "sentinel", "--live", *args]
    )
    return result.exit_code, json.loads(result.stdout)


def test_full_plan_checks_staging_and_production_tenants(
    repo: Path, azure_client: MagicMock
) -> None:
    _configure(
        repo,
        _tenant("Staging", "STAGING", STAGING_WORKSPACE),
        _tenant("Production", "PRODUCTION", PRODUCTION_WORKSPACE),
    )

    code, payload = _validate()

    assert code == 0, payload
    assert payload["status"] == "passed"
    assert payload["plan"] == "FULL"
    per_tenant = payload["queries_per_tenant"]
    assert set(per_tenant) == {"Staging", "Production"}  # type: ignore[arg-type]
    assert per_tenant["Staging"] == per_tenant["Production"] > 0  # type: ignore[index]
    assert payload["queries_validated"] == 2 * per_tenant["Staging"]  # type: ignore[index]
    workspaces = _queried_workspaces(azure_client)
    assert workspaces.count(STAGING_WORKSPACE) == per_tenant["Staging"]  # type: ignore[index]
    assert workspaces.count(PRODUCTION_WORKSPACE) == per_tenant["Production"]  # type: ignore[index]


def test_an_explicit_plan_narrows_the_check_to_its_tenants(
    repo: Path, azure_client: MagicMock
) -> None:
    _configure(
        repo,
        _tenant("Staging", "STAGING", STAGING_WORKSPACE),
        _tenant("Production", "PRODUCTION", PRODUCTION_WORKSPACE),
    )

    code, payload = _validate("--plan", "STAGING")

    assert code == 0, payload
    assert payload["plan"] == "STAGING"
    assert set(payload["queries_per_tenant"]) == {"Staging"}  # type: ignore[arg-type]
    assert set(_queried_workspaces(azure_client)) == {STAGING_WORKSPACE}


def test_a_rule_tenants_list_still_limits_the_check(repo: Path, azure_client: MagicMock) -> None:
    _configure(
        repo,
        _tenant("Staging", "STAGING", STAGING_WORKSPACE),
        _tenant("Production", "PRODUCTION", PRODUCTION_WORKSPACE),
    )
    _restrict_rule(repo, "Production")

    code, payload = _validate()

    assert code == 0, payload
    staging = _queried_workspaces(azure_client).count(STAGING_WORKSPACE)
    production = _queried_workspaces(azure_client).count(PRODUCTION_WORKSPACE)
    # Every other Sentinel rule reaches both; the restricted one reaches only Production.
    assert production == staging + 1
    assert payload["queries_per_tenant"] == {"Staging": staging, "Production": production}


def test_a_manual_tenant_is_checked_only_for_rules_that_name_it(
    repo: Path, azure_client: MagicMock
) -> None:
    _configure(repo, _tenant("Manual", "MANUAL", STAGING_WORKSPACE))
    _restrict_rule(repo, "Manual")

    code, payload = _validate()

    assert code == 0, payload
    assert payload["queries_per_tenant"] == {"Manual": 1}
    assert _queried_workspaces(azure_client) == [STAGING_WORKSPACE]


def test_no_query_sent_is_skipped_with_exit_2(repo: Path, azure_client: MagicMock) -> None:
    _configure(repo, _tenant("Manual", "MANUAL", STAGING_WORKSPACE))

    code, payload = _validate()

    assert code == 2, payload
    assert payload["status"] == "skipped"
    assert payload["status"] != "passed"
    assert payload["queries_validated"] == 0
    assert payload["queries_per_tenant"] == {}
    assert "No query was sent" in str(payload["message"])
    assert "MANUAL" in str(payload["advice"])
    azure_client.query_workspace.assert_not_called()


def test_a_plan_that_narrows_every_rule_out_is_an_ordinary_skip(
    repo: Path, azure_client: MagicMock
) -> None:
    """A production-only rule under ``--plan STAGING`` is not a broken check (exit 0).

    Found live: a staging-only rule under ``--plan PRODUCTION`` failed a CI gate.
    """
    _configure(repo, _tenant("Production", "PRODUCTION", PRODUCTION_WORKSPACE))

    code, payload = _validate("--plan", "STAGING")

    assert code == 0, payload
    assert payload["status"] == "skipped"
    assert payload["plan"] == "STAGING"
    assert payload["queries_validated"] == 0
    assert "No STAGING tenant is targeted" in str(payload["message"])
    azure_client.query_workspace.assert_not_called()


def test_a_plan_whose_rules_reach_no_tenant_at_all_exits_2(
    repo: Path, azure_client: MagicMock
) -> None:
    _configure(repo, _tenant("Manual", "MANUAL", STAGING_WORKSPACE))

    code, payload = _validate("--plan", "STAGING")

    assert code == 2, payload
    assert "No query was sent" in str(payload["message"])
    azure_client.query_workspace.assert_not_called()


def test_deploy_resolution_is_unchanged_outside_validation(repo: Path) -> None:
    """Only the read-only check reaches every tenant; FULL deploy targets stay as they were."""
    from opentide.core.registry import Opentide
    from opentide.deployment import DeploymentStrategy, TideDeployment
    from opentide.deployment.planning import read_only_tenant_resolution
    from opentide.models.deployment_enums import DetectionPlatforms

    _configure(
        repo,
        _tenant("Staging", "STAGING", STAGING_WORKSPACE),
        _tenant("Production", "PRODUCTION", PRODUCTION_WORKSPACE),
    )
    Opentide.reload()

    def _tenants() -> set[str]:
        deployment = TideDeployment(
            deployment=[SENTINEL_RULE],
            system=DetectionPlatforms.SENTINEL,
            strategy=DeploymentStrategy.FULL,
        )
        return {batch.tenant.name for batch in deployment.rule_deployment}

    assert _tenants() == set()
    with read_only_tenant_resolution():
        assert _tenants() == {"Staging", "Production"}
    assert _tenants() == set()
