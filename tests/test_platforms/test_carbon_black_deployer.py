"""Carbon Black Cloud deployer against cbc_sdk's own Report objects.

The SDK's ``Report`` keeps its IOC list and serialises it on ``update()``;
only the HTTP verbs of ``CBCloudAPI`` are replaced, so what a test reads is
the body the deployer would have sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels

pytest.importorskip("cbc_sdk")

RULE_IOC = "00000000-0000-4000-8000-000000000001"
OTHER_IOC = "00000000-0000-4000-8000-000000000002"
WATCHLIST = "Detections"


@dataclass
class _Console:
    """What the deployer sent: report bodies PUT, and report URLs deleted."""

    api: Any
    reports: list[Any] = field(default_factory=list)
    puts: list[dict[str, Any]] = field(default_factory=list)
    deletes: list[str] = field(default_factory=list)

    def add_report(self, title: str, *iocs: tuple[str, str]) -> Any:
        from cbc_sdk.enterprise_edr import Report

        data = {
            "id": f"report-{len(self.reports)}",
            "title": title,
            "description": "d",
            "severity": 3,
            "timestamp": 1,
            "iocs_v2": [
                {"id": ioc, "match_type": "query", "values": [query]} for ioc, query in iocs
            ],
        }
        # The SDK refreshes a report from the console when it is built.
        self.api.get_object = lambda *_args, **_kwargs: dict(data)
        report = Report(
            self.api, model_unique_id=data["id"], initial_data=data, from_watchlist=True
        )
        self.reports.append(report)
        return report

    def iocs(self) -> list[tuple[str, str]]:
        """The IOCs of the last report body PUT, as (id, query)."""
        return [(ioc["id"], ioc["values"][0]) for ioc in self.puts[-1]["iocs_v2"]]


@pytest.fixture
def console(monkeypatch: pytest.MonkeyPatch) -> _Console:
    from cbc_sdk.rest_api import CBCloudAPI

    api = CBCloudAPI(url="https://cbc.example", token="ABC/DEF", org_key="ORG", ssl_verify=True)
    state = _Console(api=api)
    watchlist = SimpleNamespace(name=WATCHLIST, reports=state.reports)

    def put_object(_url: str, body: dict[str, Any]) -> SimpleNamespace:
        state.puts.append(dict(body))
        return SimpleNamespace(json=dict)

    monkeypatch.setattr(api, "select", lambda *_args, **_kwargs: [watchlist])
    monkeypatch.setattr(api, "put_object", put_object)
    monkeypatch.setattr(api, "delete_object", state.deletes.append)
    return state


def _strategy(monkeypatch: pytest.MonkeyPatch, strategy: StatusStrategy) -> None:
    monkeypatch.setattr(
        "opentide.platforms.carbon_black.deployer.check_status", lambda _status: strategy
    )


def _rule(
    metadata: dict, *, report: str | None = None, watchlist: str | None = WATCHLIST
) -> DetectionRule:
    return load_rule_from_dict(
        {
            "name": "CBC Rule",
            "metadata": metadata,
            "description": "desc",
            "configurations": {
                "carbon_black_cloud": {
                    "schema": "carbon_black_cloud::3.0",
                    "status": "STAGING",
                    "query": "process_name:new.exe",
                    "watchlist": watchlist,
                    "report": report,
                }
            },
        }
    )


def _deploy(console: _Console, rule: DetectionRule) -> None:
    from opentide.platforms.carbon_black.deployer import CarbonBlackCloudDeploy

    deployer = CarbonBlackCloudDeploy.__new__(CarbonBlackCloudDeploy)
    deployer.SEVERITY_MAPPING = {"Low": 3}
    deployer.DEFAULT_WATCHLIST = ""
    tenant = SimpleNamespace(name="Org", setup=SimpleNamespace(watchlist=WATCHLIST))
    deployer.deploy_mdr(data=rule, service=console.api, tenant_config=tenant)


@pytest.mark.parametrize("report", [None, "Shared"])
def test_a_redeploy_replaces_the_rules_ioc(
    console: _Console, metadata: dict, monkeypatch: pytest.MonkeyPatch, report: str | None
) -> None:
    """``remove_iocs_by_id`` got the uuid string, which it reads as a set of characters.

    Nothing was removed, so every redeploy appended another copy of the IOC.
    """
    _strategy(monkeypatch, StatusStrategy.RELEASE)
    console.add_report(
        report or "CBC Rule", (RULE_IOC, "process_name:old.exe"), (OTHER_IOC, "process_name:b.exe")
    )

    _deploy(console, _rule(metadata, report=report))

    assert console.iocs() == [
        (OTHER_IOC, "process_name:b.exe"),
        (RULE_IOC, "process_name:new.exe"),
    ]


def test_retiring_from_a_shared_report_keeps_the_other_rules_iocs(
    console: _Console, metadata: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strategy(monkeypatch, StatusStrategy.DELETION)
    console.add_report("Shared", (RULE_IOC, "process_name:old.exe"), (OTHER_IOC, "b"))

    _deploy(console, _rule(metadata, report="Shared"))

    assert console.iocs() == [(OTHER_IOC, "b")]
    assert console.deletes == []


def test_retiring_never_deletes_a_shared_report_holding_another_rules_ioc(
    console: _Console, metadata: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A shared report with one IOC was deleted whoever that IOC belonged to."""
    _strategy(monkeypatch, StatusStrategy.DELETION)
    console.add_report("Shared", (OTHER_IOC, "b"))

    _deploy(console, _rule(metadata, report="Shared"))

    assert console.deletes == []
    assert console.iocs() == [(OTHER_IOC, "b")]


def test_retiring_the_last_ioc_of_a_shared_report_deletes_it(
    console: _Console, metadata: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strategy(monkeypatch, StatusStrategy.DELETION)
    console.add_report("Shared", (RULE_IOC, "process_name:old.exe"))

    _deploy(console, _rule(metadata, report="Shared"))

    assert console.deletes == ["/threathunter/watchlistmgr/v3/orgs/ORG/reports/report-0"]
    assert console.puts == []


def _tenant(name: str, watchlist: str) -> ConfigurationModels.Systems.CarbonBlackCloud.Tenant:
    Tenant = ConfigurationModels.Systems.CarbonBlackCloud.Tenant
    return Tenant(
        name=name,
        description=name,
        setup=Tenant.Setup(
            ssl=True, url="https://cbc.example", org_key="ORG", token="ABC/DEF", watchlist=watchlist
        ),
    )


def test_a_rule_without_a_watchlist_uses_its_own_tenants(
    console: _Console, metadata: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback watchlist was the first tenant's, for every tenant.

    A second tenant failed with "nonexistent Watchlist", or deployed into
    a watchlist of the same name that was not the one it configured.
    """
    from opentide.platforms.carbon_black import client
    from opentide.platforms.carbon_black.deployer import CarbonBlackCloudDeploy

    first = _tenant("First", "First tenant's watchlist")
    second = _tenant("Second", WATCHLIST)
    systems = SimpleNamespace(CarbonBlackCloud=SimpleNamespace(tenants=[first, second]))
    registry = SimpleNamespace(Configurations=SimpleNamespace(Systems=systems))
    monkeypatch.setattr(client, "Opentide", registry)
    _strategy(monkeypatch, StatusStrategy.RELEASE)
    console.add_report("CBC Rule", (RULE_IOC, "process_name:old.exe"))

    CarbonBlackCloudDeploy().deploy_mdr(
        data=_rule(metadata, watchlist=None), service=console.api, tenant_config=second
    )

    assert console.iocs() == [(RULE_IOC, "process_name:new.exe")]


def test_an_org_without_any_watchlist_names_the_missing_watchlist(
    console: _Console, metadata: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no watchlist at all the lookup fell through and failed on ``None.add_reports``."""
    monkeypatch.setattr(console.api, "select", lambda *_args, **_kwargs: [])
    _strategy(monkeypatch, StatusStrategy.RELEASE)

    with pytest.raises(RuntimeError, match="nonexistent Watchlist"):
        _deploy(console, _rule(metadata))


def test_the_deploy_loop_reports_each_rule_and_a_failed_one_stops_it(
    console: _Console, metadata: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rule that raises is that rule's failure, with the error as the platform says it (#675)."""
    from tests.deploy_events_support import Recorder

    from opentide.core import deploy_events
    from opentide.platforms.carbon_black import deployer as module
    from opentide.platforms.carbon_black.deployer import CarbonBlackCloudDeploy

    tenant = _tenant("Org", WATCHLIST)
    rules = [_rule({**metadata, "uuid": f"00000000-0000-4000-8000-00000000000{n}"}) for n in (1, 2)]
    batch = SimpleNamespace(tenant=tenant, rules=rules)
    monkeypatch.setattr(
        module, "TideDeployment", lambda **_kwargs: SimpleNamespace(rule_deployment=[batch])
    )
    monkeypatch.setattr(module, "without_legacy_external_ids", lambda rules, platform: rules)
    monkeypatch.setattr(
        module, "CarbonBlackCloudService", lambda _tenant: SimpleNamespace(service=None)
    )

    def deploy_mdr(
        self: object, *, data: DetectionRule, service: object, tenant_config: object
    ) -> None:
        if data.metadata.uuid.endswith("1"):
            raise RuntimeError("watchlist is full")

    monkeypatch.setattr(CarbonBlackCloudDeploy, "deploy_mdr", deploy_mdr)
    recorder = Recorder()
    with deploy_events.listen(recorder), pytest.raises(RuntimeError, match="watchlist is full"):
        CarbonBlackCloudDeploy().deploy(rules, (StatusStrategy.RELEASE,))
    assert recorder.outcomes() == [(rules[0].metadata.uuid, "failed")]
    assert recorder.results[0].platform == "carbon_black_cloud"
    assert recorder.results[0].tenant == "Org"
    assert recorder.results[0].error == "RuntimeError: watchlist is full"
