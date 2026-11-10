"""What the oracle (the frozen Python CLI) would send for every rule.

Run by `cargo xtask payloads diff --against python` with the oracle's
interpreter, isolated (`python -I probe.py REQUEST RESULT`), once per fixture
workspace. REQUEST is JSON: {"repo": DIR, "rules": [{"uuid", "path"}]}, the
rules the Rust index holds. Each is read as the registry reads it
(`load_rule_from_dict`); a rule the data model refuses is reported as
`unloadable`, with why. For every other rule, and every platform block it has,
the probe writes:

- `compile`: for a platform whose body opentide compiles from the rule alone
  (Sentinel, Elastic, Sysdig), the body `compile_offline` gives (the dry run's
  tenant), as compact JSON in the oracle's key order, or the error a dry run
  reports (`compile_diagnostic`: code, message, help); `{}` for the others;
- `tenants`: for each configured tenant of the platform, the same for that
  tenant (Sentinel's tenant name selects exclusions; Elastic's `setup` adds
  index, tags and suppression; Sysdig's adds tags). For a platform whose
  deployer builds the body from the tenant and the deployment state (Defender,
  Splunk, SentinelOne, CrowdStrike, HarfangLab, Carbon Black), the deployer
  runs against a recording stand-in for the platform's client, and the body is
  the list of writes it sends, each `{"method", "url", "body"}` (`DEPLOYERS`);
- `preview`: the dry run's payload entry (`preview_rule_deployment`).

Where the oracle's own client fails before it sends anything, the tenant's
outcome also has `fault`, the failure (`Type: message`): the probe gives the
client what it lacked and records the body the deployer builds, and
`xtask payloads` requires a `[[fault]]` approval of that failure. HarfangLab's
client reads its identifier as `Systems.HarfangLab`, which the registry has
no attribute for, so the oracle's HarfangLab deploy fails on every tenant.

A deployer acts on the deployment state's id for the rule on the tenant:
update (or delete, for a DELETION status) when one is recorded, create when
none is, and nothing for a DELETION or DISABLEMENT status without one. The
stand-in answers every write with success and holds nothing: a Splunk saved
search, a Carbon Black report and a HarfangLab Sigma rule are absent, so they
are created; the Carbon Black watchlist the rule names exists. Ids the
deployer would record are not written. Splunk's random schedule minute and
hour are 7 and its clock 03:04 UTC; Carbon Black's report timestamp is
`CBC_TIMESTAMP`.

Standard library and the oracle only; no output on stdout is relied on.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from typing import Any

OFFLINE = ("sentinel", "elastic", "sysdig")
DEPLOYERS = (
    "defender_for_endpoint",
    "splunk",
    "sentinel_one",
    "crowdstrike",
    "harfanglab",
    "carbon_black_cloud",
)
PLATFORMS = OFFLINE + DEPLOYERS
DISPLAY = {
    "sentinel": "Sentinel",
    "elastic": "Elastic",
    "sysdig": "Sysdig",
    "defender_for_endpoint": "Defender for Endpoint",
    "splunk": "Splunk",
    "sentinel_one": "SentinelOne",
    "crowdstrike": "CrowdStrike",
    "harfanglab": "HarfangLab",
    "carbon_black_cloud": "Carbon Black Cloud",
}
ATTRIBUTES = {
    "sentinel": "Sentinel",
    "elastic": "Elastic",
    "sysdig": "Sysdig",
    "defender_for_endpoint": "DefenderForEndpoint",
    "splunk": "Splunk",
    "sentinel_one": "SentinelOne",
    "crowdstrike": "Crowdstrike",
    # The registry snake-cases the attribute: `HarfangLab` would read `harfang_lab`.
    "harfanglab": "Harfanglab",
    "carbon_black_cloud": "CarbonBlackCloud",
}
#: The Carbon Black report's `timestamp` (`Report.create` takes the clock's).
CBC_TIMESTAMP = 1767225600


def compact(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def body_for(platform: str, rule: Any, tenant: Any) -> object:
    """The body of *rule* on *platform*: the dry run's, or *tenant*'s."""
    if tenant is None:
        from opentide.deployment.preview import compile_offline

        return compile_offline(platform, rule)
    if platform == "sentinel":
        from opentide.platforms.sentinel.deployer import SentinelDeploy

        return SentinelDeploy().compile_deployment(service=None, data=rule, tenant=tenant.name)
    if platform == "sysdig":
        from opentide.platforms.sysdig.compile import api_body
        from opentide.platforms.sysdig.deployer import SysdigDeploy

        return api_body(SysdigDeploy().compile_deployment(rule, tenant))
    from opentide.platforms.elastic.compile import compile_rule

    return compile_rule(rule, tenant)


class Answer:
    """A platform's answer to a write: success, with every id a deployer reads."""

    def __init__(self, status: int) -> None:
        self.status_code = status
        self.text = ""

    def json(self) -> dict[str, object]:
        return {"id": "1", "data": {"id": 1}, "resources": [{"id": "1"}]}


class Session:
    """A client's HTTP session that records each write and answers it."""

    def __init__(self, statuses: dict[str, int], writes: list[dict[str, object]]) -> None:
        self.statuses = statuses
        self.writes = writes
        self.headers: dict[str, str] = {}

    def _send(self, method: str, url: str, **kwargs: Any) -> Answer:
        from urllib.parse import urlencode

        body = kwargs.get("json")
        data = kwargs.get("data")
        if body is None and data is not None:
            body = json.loads(data)
        if kwargs.get("params"):
            url = f"{url}?{urlencode(kwargs['params'])}"
        self.writes.append({"method": method, "url": url, "body": body})
        return Answer(self.statuses[method])

    def post(self, url: str, **kwargs: Any) -> Answer:
        return self._send("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Answer:
        return self._send("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Answer:
        return self._send("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Answer:
        return self._send("DELETE", url, **kwargs)


class SavedSearch:
    """A Splunk saved search the deployer created: its updates are writes."""

    def __init__(self, name: str, writes: list[dict[str, object]]) -> None:
        self.name = name
        self.writes = writes

    def update(self, **params: Any) -> None:
        self.writes.append(
            {"method": "POST", "url": f"saved/searches/{self.name}", "body": dict(params)}
        )


class SavedSearches:
    """Splunk's saved searches, none of them present."""

    def __init__(self, writes: list[dict[str, object]]) -> None:
        self.writes = writes

    def __getitem__(self, name: str) -> SavedSearch:
        raise KeyError(name)

    def create(self, name: str, **params: Any) -> SavedSearch:
        self.writes.append(
            {"method": "POST", "url": "saved/searches", "body": {"name": name, **params}}
        )
        return SavedSearch(name, self.writes)

    def delete(self, name: str) -> None:
        self.writes.append({"method": "DELETE", "url": f"saved/searches/{name}", "body": None})


class Splunk:
    """A splunklib service."""

    def __init__(self, writes: list[dict[str, object]]) -> None:
        self.saved_searches = SavedSearches(writes)


class Watchlist:
    """A Carbon Black watchlist with no report."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.reports: list[Any] = []

    def add_reports(self, reports: list[Any]) -> None:
        pass


class CarbonBlack:
    """A CBCloudAPI whose org holds the watchlist the rule names, empty."""

    def __init__(self, org_key: str, writes: list[dict[str, object]]) -> None:
        from types import SimpleNamespace

        self.credentials = SimpleNamespace(org_key=org_key)
        self.writes = writes

    def select(self, _model: Any) -> list[Watchlist]:
        return self.watchlists

    def post_object(self, url: str, body: dict[str, object]) -> Answer:
        self.writes.append({"method": "POST", "url": url, "body": json.loads(compact(body))})
        return Answer(200)


def strategy_of(status: object) -> Any:
    from opentide.deployment import check_status

    return check_status(str(status))


def action_for(platform: str, rule: Any, tenant: Any, status: object) -> Any:
    """What the deployer does on *tenant*: the deployment state's answer."""
    from opentide.deployment.external_ids import ExternalIdAction
    from opentide.models.deployment_enums import StatusStrategy
    from opentide.states.deployment import DeploymentState

    known = DeploymentState.load(str(rule.metadata.uuid)).get(platform, tenant.name)
    strategy = strategy_of(status)
    if known is not None:
        return ExternalIdAction(
            "delete" if strategy is StatusStrategy.DELETION else "update", known
        )
    if strategy in (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT):
        return None
    return ExternalIdAction("create")


def deployer_writes(
    platform: str, rule: Any, tenant: Any, faults: list[str]
) -> list[dict[str, object]]:
    """The writes the deployer of *platform* sends for *rule* to *tenant*.

    A failure of the oracle's own client that the probe works around is
    appended to *faults*.
    """
    writes: list[dict[str, object]] = []
    block = getattr(rule.configurations, platform)
    if platform == "defender_for_endpoint":
        from opentide.platforms.defender_for_endpoint import client, deployer

        client.TenantSession = lambda verify: Session(
            {"POST": 201, "PATCH": 200, "DELETE": 204}, writes
        )
        client.DefenderForEndpointService._connect_to_tenant = lambda *_: "token"
        action = action_for(platform, rule, tenant, block.status)
        if action is not None:
            deployer.record_created = deployer.record_deleted = lambda **_: None
            service = client.DefenderForEndpointService(tenant)
            deployer.DefenderForEndpointDeploy().deploy_mdr(rule, service, tenant.name, action)
        return writes
    if platform in ("sentinel_one", "crowdstrike"):
        if platform == "sentinel_one":
            from opentide.platforms.sentinel_one import client, deployer

            deploy = deployer.SentinelOneDeploy()
            service_class = client.SentinelOneService
        else:
            from opentide.platforms.crowdstrike import client, deployer

            deploy = deployer.CrowdstrikeDeploy()
            service_class = client.CrowdstrikeService
            service_class._get_access_token = lambda *_: "token"
        client.TenantSession = lambda verify: Session(
            {"POST": 200, "PUT": 200, "PATCH": 200, "DELETE": 200}, writes
        )
        action = action_for(platform, rule, tenant, block.status)
        if action is not None:
            deployer.record_created = deployer.record_deleted = lambda **_: None
            deploy.deploy_mdr(rule, service_class(tenant), tenant, action)
        return writes
    if platform == "harfanglab":
        from opentide.platforms.harfanglab import client, deployer

        client.TenantSession = lambda verify: Session(
            {"POST": 201, "PUT": 200, "PATCH": 200, "DELETE": 204}, writes
        )
        is_sigma = block.sigma is not None
        kind = "Sigma" if is_sigma else "YARA" if block.yara is not None else None
        if kind != tenant.setup.type:
            return writes
        try:
            service = client.HarfangLabService(tenant)
        except Exception as exc:  # the oracle's own client fails: a fault
            # The client reads its identifier as `Systems.HarfangLab`, which
            # the registry has no attribute for (it snake-cases it
            # `harfang_lab`). The fault is recorded; the body compared is the
            # deployer's, with the client given the identifier.
            from types import SimpleNamespace

            faults.append(f"{type(exc).__name__}: {exc}")
            identifier = SimpleNamespace(platform=SimpleNamespace(identifier="harfanglab"))
            registry = client.Opentide
            client.Opentide = SimpleNamespace(
                Configurations=SimpleNamespace(Systems=SimpleNamespace(HarfangLab=identifier))
            )
            try:
                service = client.HarfangLabService(tenant)
            finally:
                client.Opentide = registry
        deployer.HarfangLabDeploy().deploy_mdr(rule, service, tenant)
        return writes
    if platform == "splunk":
        from opentide.platforms.splunk import client, deployer

        client.randrange = lambda _limit: 7
        client.utc_now = lambda: __import__("datetime").datetime(
            2026, 1, 2, 3, 4, 5, tzinfo=__import__("datetime").timezone.utc
        )
        deploy = deployer.SplunkDeploy()
        deploy.DEBUG_STEP = False
        deploy.use_tenant(tenant)
        deploy.deploy_mdr(rule, Splunk(writes), tenant)
        return writes
    from cbc_sdk.enterprise_edr import threat_intelligence

    from opentide.platforms.carbon_black import deployer

    threat_intelligence.time = __import__("types").SimpleNamespace(time=lambda: CBC_TIMESTAMP)
    service = CarbonBlack(tenant.setup.org_key, writes)
    name = block.watchlist or tenant.setup.watchlist
    service.watchlists = [Watchlist(name)] if name else []
    deployer.CarbonBlackCloudDeploy().deploy_mdr(rule, service, tenant)
    return writes


def outcome(platform: str, rule: Any, tenant: Any = None) -> dict[str, object]:
    from opentide.deployment.preview import compile_diagnostic

    if platform in DEPLOYERS and tenant is None:
        return {}
    faults: list[str] = []
    try:
        if platform in DEPLOYERS:
            body: object = deployer_writes(platform, rule, tenant, faults)
        else:
            body = body_for(platform, rule, tenant)
    except Exception as exc:  # every failure is an outcome to compare
        code, message, hint = compile_diagnostic(exc, DISPLAY[platform])
        fault = {"fault": faults[0]} if faults else {}
        return {**fault, "error": {"code": code, "message": message, "help": hint}}
    fault = {"fault": faults[0]} if faults else {}
    return {**fault, "body": compact(body)}


def main() -> int:
    request_path, result_path = sys.argv[1], sys.argv[2]
    with open(request_path, encoding="utf-8") as handle:
        request = json.load(handle)
    repo = request["repo"]
    os.chdir(repo)
    os.environ["OPENTIDE_REPO_ROOT"] = repo

    from pathlib import Path

    from opentide.core.environment import defer_missing_envvars
    from opentide.core.io import load_yaml
    from opentide.core.registry import Opentide
    from opentide.deployment.preview import preview_rule_deployment
    from opentide.loading.rule_loader import load_rule_from_dict

    rules: list[dict[str, object]] = []
    unloadable: list[dict[str, str]] = []
    with (
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()),
        defer_missing_envvars(),
    ):
        Opentide.initialise()
        systems = Opentide.Configurations.Systems
        tenants: dict[str, list[Any]] = {}
        for platform, attribute in ATTRIBUTES.items():
            try:
                tenants[platform] = list(
                    getattr(getattr(systems, attribute), "tenants", None) or []
                )
            except Exception:  # a platform file the oracle refuses has no tenants
                tenants[platform] = []
        for listed in request["rules"]:
            uuid, path = listed["uuid"], Path(listed["path"])
            try:
                rule = load_rule_from_dict(load_yaml(path), file=path)
            except Exception as exc:  # the oracle refuses the rule
                unloadable.append({"uuid": uuid, "error": f"{type(exc).__name__}: {exc}"})
                continue
            if rule.configurations is None:
                continue
            for platform in PLATFORMS:
                if getattr(rule.configurations, platform, None) is None:
                    continue
                entry: dict[str, object] = {
                    "uuid": str(uuid),
                    "file": str(getattr(rule, "file", "") or ""),
                    "platform": platform,
                    "compile": outcome(platform, rule),
                    "preview": compact(preview_rule_deployment(platform, rule)),
                }
                entry["tenants"] = [
                    {"tenant": tenant.name, **outcome(platform, rule, tenant)}
                    for tenant in tenants[platform]
                ]
                rules.append(entry)
    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump({"rules": rules, "unloadable": unloadable}, handle, ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
