"""Live query validation checks a rule where a deploy sends it, and never passes on nothing.

``validate query --live`` resolves tenants as ``deploy`` does: a tenant takes a
rule when its ``strategies`` accept a run strategy that deploys the strategy
the rule's status maps to. Without ``--strategy`` the run strategies are
``PREVIEW`` and ``RELEASE``, so every rule is checked on every tenant it is
deployed to. A ``manual`` tenant is reached only by the rules that list it,
and a rule's ``tenants`` list limits it. Sending no query at all is a skip
that exits 2, never ``passed`` (#547).

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

PREVIEW_WORKSPACE = "11111111-1111-4111-8111-111111111111"
RELEASE_WORKSPACE = "22222222-2222-4222-8222-222222222222"
BOTH_WORKSPACE = "33333333-3333-4333-8333-333333333333"
SENTINEL_RULE = "00000000-0000-4000-8003-000000000001"
SENTINEL_RULE_FILE = "Objects/Detection Rules/rule-0001-sentinel-kql.yaml"


def _tenant(
    name: str,
    workspace_id: str,
    *,
    strategies: tuple[str, ...] | None = None,
    manual: bool = False,
) -> str:
    """A Sentinel tenant; ``strategies=None`` omits the key, so it accepts both."""
    targeting = ""
    if strategies is not None:
        targeting += f"strategies = {json.dumps(list(strategies))}\n"
    if manual:
        targeting += "manual = true\n"
    return f"""
[[tenants]]
name = "{name}"
description = "{name} workspace"
{targeting}[tenants.setup]
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
    path = repo / SENTINEL_RULE_FILE
    listed = "".join(f"      - {name}\n" for name in tenants)
    text = path.read_text(encoding="utf-8").replace(
        "    status: STAGING\n", f"    status: STAGING\n    tenants:\n{listed}", 1
    )
    path.write_text(text, encoding="utf-8")


def _set_status(repo: Path, status: str) -> None:
    """Give the corpus Sentinel rule's platform block another status.

    The other corpus Sentinel rule (``rule-0008``) keeps ``STAGING``.
    """
    path = repo / SENTINEL_RULE_FILE
    text = path.read_text(encoding="utf-8").replace(
        "    status: STAGING\n", f"    status: {status}\n", 1
    )
    path.write_text(text, encoding="utf-8")


def _add_universal_status(repo: Path, name: str) -> None:
    """Configure a status that maps to ``UNIVERSAL``, which no default status does."""
    from opentide.core.root import get_data_root

    bundled = (get_data_root() / "configurations/deployment.toml").read_text(encoding="utf-8")
    status = f'[[statuses]]\nname = "{name}"\ndescription = "Both"\nstrategy = "UNIVERSAL"\n\n'
    path = repo / ".opentide/configurations/deployment.toml"
    path.write_text(bundled.replace("[promotion]", status + "[promotion]", 1), encoding="utf-8")


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


def test_a_rule_is_checked_on_the_tenants_its_status_deploys_to(
    repo: Path, azure_client: MagicMock
) -> None:
    """A STAGING rule (PREVIEW) on the preview tenant, a PRODUCTION rule (RELEASE) on release."""
    _configure(
        repo,
        _tenant("Preview", PREVIEW_WORKSPACE, strategies=("PREVIEW",)),
        _tenant("Release", RELEASE_WORKSPACE, strategies=("RELEASE",)),
    )
    _set_status(repo, "PRODUCTION")

    code, payload = _validate()

    assert code == 0, payload
    assert payload["status"] == "passed"
    assert payload["strategies"] == ["PREVIEW", "RELEASE"]
    assert "plan" not in payload
    assert payload["queries_per_tenant"] == {"Preview": 1, "Release": 1}
    assert payload["queries_validated"] == 2
    assert sorted(_queried_workspaces(azure_client)) == [PREVIEW_WORKSPACE, RELEASE_WORKSPACE]


def test_a_tenant_without_strategies_takes_every_rule(repo: Path, azure_client: MagicMock) -> None:
    _configure(
        repo,
        _tenant("Preview", PREVIEW_WORKSPACE, strategies=("PREVIEW",)),
        _tenant("Both", BOTH_WORKSPACE),
    )
    _set_status(repo, "PRODUCTION")

    code, payload = _validate()

    assert code == 0, payload
    # rule-0008 (STAGING) reaches both tenants; rule-0001 (PRODUCTION) only Both.
    assert payload["queries_per_tenant"] == {"Preview": 1, "Both": 2}
    workspaces = _queried_workspaces(azure_client)
    assert workspaces.count(PREVIEW_WORKSPACE) == 1
    assert workspaces.count(BOTH_WORKSPACE) == 2


def test_a_tenant_listing_both_strategies_takes_every_rule(
    repo: Path, azure_client: MagicMock
) -> None:
    _configure(repo, _tenant("Both", BOTH_WORKSPACE, strategies=("PREVIEW", "RELEASE")))
    _set_status(repo, "PRODUCTION")

    code, payload = _validate()

    assert code == 0, payload
    assert payload["queries_per_tenant"] == {"Both": 2}


def test_an_explicit_strategy_narrows_the_check_to_its_rules_and_tenants(
    repo: Path, azure_client: MagicMock
) -> None:
    _configure(
        repo,
        _tenant("Preview", PREVIEW_WORKSPACE, strategies=("PREVIEW",)),
        _tenant("Release", RELEASE_WORKSPACE, strategies=("RELEASE",)),
    )
    _set_status(repo, "PRODUCTION")

    code, payload = _validate("--strategy", "PREVIEW")

    assert code == 0, payload
    assert payload["strategies"] == ["PREVIEW"]
    assert payload["queries_per_tenant"] == {"Preview": 1}
    assert _queried_workspaces(azure_client) == [PREVIEW_WORKSPACE]


@pytest.mark.parametrize("value", ["STAGING", "FULL", "universal"])
def test_a_strategy_that_is_not_deployable_is_refused(
    repo: Path, azure_client: MagicMock, value: str
) -> None:
    _configure(repo, _tenant("Both", BOTH_WORKSPACE))

    code, payload = _validate("--strategy", value)

    assert code == 2, payload
    assert payload["status"] == "failed"
    assert "is not a deployable strategy" in str(payload["message"])
    azure_client.query_workspace.assert_not_called()


def test_a_rule_tenants_list_still_limits_the_check(repo: Path, azure_client: MagicMock) -> None:
    _configure(
        repo,
        _tenant("Preview", PREVIEW_WORKSPACE, strategies=("PREVIEW",)),
        _tenant("Both", BOTH_WORKSPACE),
    )
    _restrict_rule(repo, "Both")

    code, payload = _validate()

    assert code == 0, payload
    # rule-0008 reaches both tenants; the restricted rule-0001 reaches only Both.
    assert payload["queries_per_tenant"] == {"Preview": 1, "Both": 2}
    workspaces = _queried_workspaces(azure_client)
    assert workspaces.count(PREVIEW_WORKSPACE) == 1
    assert workspaces.count(BOTH_WORKSPACE) == 2


def test_a_listed_tenant_must_still_accept_the_rule_strategy(
    repo: Path, azure_client: MagicMock
) -> None:
    """Listing a tenant does not deploy a PREVIEW rule to a RELEASE-only tenant."""
    _configure(
        repo,
        _tenant("Preview", PREVIEW_WORKSPACE, strategies=("PREVIEW",)),
        _tenant("Release", RELEASE_WORKSPACE, strategies=("RELEASE",)),
    )
    _restrict_rule(repo, "Release")

    code, payload = _validate()

    assert code == 0, payload
    # Only rule-0008, on the preview tenant: rule-0001 is listed nowhere it deploys.
    assert payload["queries_per_tenant"] == {"Preview": 1}
    assert _queried_workspaces(azure_client) == [PREVIEW_WORKSPACE]


def test_a_manual_tenant_is_checked_only_for_rules_that_name_it(
    repo: Path, azure_client: MagicMock
) -> None:
    _configure(repo, _tenant("Manual", PREVIEW_WORKSPACE, manual=True))
    _restrict_rule(repo, "Manual")

    code, payload = _validate()

    assert code == 0, payload
    assert payload["queries_per_tenant"] == {"Manual": 1}
    assert _queried_workspaces(azure_client) == [PREVIEW_WORKSPACE]


def test_no_query_sent_is_skipped_with_exit_2(repo: Path, azure_client: MagicMock) -> None:
    _configure(repo, _tenant("Manual", PREVIEW_WORKSPACE, manual=True))

    code, payload = _validate()

    assert code == 2, payload
    assert payload["status"] == "skipped"
    assert payload["status"] != "passed"
    assert payload["strategies"] == ["PREVIEW", "RELEASE"]
    assert payload["queries_validated"] == 0
    assert payload["queries_per_tenant"] == {}
    assert "No query was sent" in str(payload["message"])
    assert "manual" in str(payload["advice"])
    assert "strategies" in str(payload["advice"])
    azure_client.query_workspace.assert_not_called()


def test_rules_no_tenant_accepts_are_skipped_with_exit_2(
    repo: Path, azure_client: MagicMock
) -> None:
    """STAGING rules and only a RELEASE tenant: no deploy would ever send them anywhere."""
    _configure(repo, _tenant("Release", RELEASE_WORKSPACE, strategies=("RELEASE",)))

    code, payload = _validate()

    assert code == 2, payload
    assert payload["status"] == "skipped"
    assert "No query was sent" in str(payload["message"])
    azure_client.query_workspace.assert_not_called()


def test_a_strategy_that_narrows_every_rule_out_is_an_ordinary_skip(
    repo: Path, azure_client: MagicMock
) -> None:
    """Every Sentinel rule is STAGING, so ``--strategy RELEASE`` selects none (exit 0)."""
    _configure(repo, _tenant("Release", RELEASE_WORKSPACE, strategies=("RELEASE",)))

    code, payload = _validate("--strategy", "RELEASE")

    assert code == 0, payload
    assert payload["status"] == "skipped"
    assert payload["strategies"] == ["RELEASE"]
    assert "maps to the run's strategies" in str(payload["message"])
    azure_client.query_workspace.assert_not_called()


def test_a_strategy_that_narrows_every_tenant_out_is_an_ordinary_skip(
    repo: Path, azure_client: MagicMock
) -> None:
    """A UNIVERSAL rule checked with ``--strategy RELEASE`` on a PREVIEW-only tenant (exit 0).

    Found live: a rule a gate's strategy does not send anywhere failed the CI gate.
    """
    _add_universal_status(repo, "SHARED")
    _set_status(repo, "SHARED")
    _configure(repo, _tenant("Preview", PREVIEW_WORKSPACE, strategies=("PREVIEW",)))

    code, payload = _validate("--strategy", "RELEASE")

    assert code == 0, payload
    assert payload["status"] == "skipped"
    assert payload["strategies"] == ["RELEASE"]
    assert payload["queries_validated"] == 0
    assert "goes to a tenant accepting RELEASE" in str(payload["message"])
    azure_client.query_workspace.assert_not_called()

    code, payload = _validate()

    assert code == 0, payload
    assert payload["queries_per_tenant"] == {"Preview": 2}


def test_a_strategy_whose_rules_reach_no_tenant_at_all_exits_2(
    repo: Path, azure_client: MagicMock
) -> None:
    _configure(repo, _tenant("Manual", PREVIEW_WORKSPACE, manual=True))

    code, payload = _validate("--strategy", "PREVIEW")

    assert code == 2, payload
    assert payload["strategies"] == ["PREVIEW"]
    assert "No query was sent" in str(payload["message"])
    azure_client.query_workspace.assert_not_called()


def test_an_inherited_deployment_plan_is_refused(
    repo: Path, azure_client: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.models.deployment_enums import removed_plan_message

    _configure(repo, _tenant("Both", BOTH_WORKSPACE))
    monkeypatch.setenv("DEPLOYMENT_PLAN", "FULL")

    code, payload = _validate()

    assert code == 2, payload
    assert payload["message"] == removed_plan_message("FULL")
    azure_client.query_workspace.assert_not_called()


def test_a_tenant_still_using_deployment_is_refused_with_its_replacement(
    repo: Path, azure_client: MagicMock
) -> None:
    _configure(
        repo,
        _tenant("Staging", PREVIEW_WORKSPACE).replace(
            'description = "Staging workspace"\n',
            'description = "Staging workspace"\ndeployment = "STAGING"\n',
        ),
    )

    code, payload = _validate()

    assert code == 1, payload
    assert payload["status"] == "failed"
    message = str(payload["message"])
    assert "the tenant key 'deployment' was removed in 0.17.0" in message
    assert 'strategies = ["PREVIEW"]' in message
    azure_client.query_workspace.assert_not_called()


def test_deploy_resolves_the_same_tenants_as_validation(repo: Path) -> None:
    """``TideDeployment`` is what both commands use: the run strategies pick the tenants."""
    from opentide.core.registry import Opentide
    from opentide.deployment import TideDeployment
    from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES, DetectionPlatforms
    from opentide.models.deployment_enums import StatusStrategy as S

    _configure(
        repo,
        _tenant("Preview", PREVIEW_WORKSPACE, strategies=("PREVIEW",)),
        _tenant("Release", RELEASE_WORKSPACE, strategies=("RELEASE",)),
        _tenant("Manual", BOTH_WORKSPACE, manual=True),
    )
    Opentide.reload()

    def _tenants(run: tuple[S, ...]) -> set[str]:
        deployment = TideDeployment(
            deployment=[SENTINEL_RULE], system=DetectionPlatforms.SENTINEL, strategies=run
        )
        return {batch.tenant.name for batch in deployment.rule_deployment}

    # The rule is STAGING, which maps to PREVIEW.
    assert _tenants(DEPLOYABLE_STRATEGIES) == {"Preview"}
    assert _tenants((S.PREVIEW,)) == {"Preview"}
    assert _tenants((S.RELEASE,)) == set()
