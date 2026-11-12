"""The Python Defender for Endpoint client, driven through each scenario (UC-4.2).

``cargo xtask cassettes record defender/<scenario>`` runs this with the oracle's
interpreter (the frozen Python implementation) behind the recording proxy, against
``tenant.py``. ``python client.py fixture <path>`` writes, instead, the inputs the
scenarios give the client (bodies, queries, windows) for the Rust connector's
tests (``crates/opentide-connectors/tests/defender.rs``), which must send what this
sent, byte for byte.

Scenarios:

- ``deploy``: sign in; create a rule whose alert names a user asset (refused, then
  created with the safer configuration); update it; update a rule Graph does not
  know (404, no body); delete the rule.
- ``query``: ``opentide query``'s runner: a search over a fixed window, one row past
  the limit; a syntax error (400); a missing permission (403); a gateway's page (502).
- ``validate``: ``validate query --live``'s check (a search for one row) of a query
  with the columns a custom detection needs and of one without them.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from opentide.models.system_config import ConfigurationModels as C

from opentide.platforms.defender_for_endpoint import client as mde
from opentide.platforms.defender_for_endpoint import runner as mde_runner
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow

WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)
CHECK_WINDOW = TimeWindow(
    datetime(2026, 10, 27, 7, 59, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)

QUERIES = [
    {"text": "DeviceProcessEvents\n| where FileName =~ 'powershell.exe'", "limit": 1},
    {"text": "DeviceProcessEvents | whre x", "limit": 100},
    {"text": "// forbidden\nEmailEvents", "limit": 100},
    {"text": "// gateway\nDeviceEvents", "limit": 100},
]
CHECKS = [
    "DeviceProcessEvents\n| project Timestamp, DeviceId, ReportId",
    "DeviceProcessEvents\n| project Timestamp, DeviceName",
]


def _tenant() -> Any:
    setup = C.Systems.DefenderForEndpoint.Tenant.Setup(
        ssl=True,
        tenant_id="contoso-tenant-id",
        client_id="opentide-app-id",
        client_secret=os.environ.get("DEFENDER_CLIENT_SECRET", "fixture"),
    )
    return C.Systems.DefenderForEndpoint.Tenant(name="xdr", description="", setup=setup)


def _rule() -> Any:
    rule = mde.DetectionRule
    template = rule.DetectionAction.AlertTemplate
    action = rule.DetectionAction
    return rule(
        displayName="Encoded PowerShell — Ünïcode",
        isEnabled=True,
        queryCondition=rule.QueryCondition(
            queryText='DeviceProcessEvents\n| where ProcessCommandLine has "-enc"'
        ),
        schedule=rule.Schedule(period="1H"),
        detectionAction=action(
            alertTemplate=template(
                title="Encoded PowerShell",
                description="A process ran PowerShell with an encoded command.",
                severity=mde.Severity.high,
                category="Execution",
                mitreTechniques=[],
                impactedAssets=[
                    template.ImpactedAsset(
                        odata_type="#microsoft.graph.security.impactedUserAsset",
                        identifier="accountUpn",
                    ),
                    template.ImpactedAsset(
                        odata_type="#microsoft.graph.security.impactedDeviceAsset",
                        identifier="deviceName",
                    ),
                ],
                recommendedActions=None,
            ),
            responseActions=[
                action.ResponseActionIsolateDevice(
                    odata_type="#microsoft.graph.security.isolateDeviceResponseAction",
                    isolationType="full",
                ),
                action.ResponseAction(
                    odata_type="#microsoft.graph.security.disableUserResponseAction",
                    identifier="accountSid",
                ),
            ],
        ),
    )


def _body(rule: Any) -> Any:
    """The body the client sends for *rule*, as ``create_detection_rule`` builds it."""
    return json.loads(json.dumps(asdict(rule)).replace("odata_type", "@odata.type"))


def _request(text: str, window: TimeWindow, limit: int) -> QueryRequest:
    return QueryRequest(platform="defender_for_endpoint", text=text, window=window, limit=limit)


def deploy() -> None:
    service = mde.DefenderForEndpointService(_tenant())
    remote = service.create_detection_rule(_rule())
    service.update_detection_rule(_rule(), remote)
    with contextlib.suppress(mde.Errors.DetectionRuleUpdateFailed):
        service.update_detection_rule(_rule(), 99)
    service.delete_detection_rule(remote)


def query() -> None:
    # "Now" is the end of the window, so the 30-day retention check is stable.
    mde_runner.utc_now = lambda: WINDOW.end
    runner = mde_runner.DefenderQueryRunner()
    tenant = _tenant()
    for item in QUERIES:
        with contextlib.suppress(QueryRefused):
            runner.run(_request(item["text"], WINDOW, item["limit"]), tenant)


def validate() -> None:
    mde_runner.utc_now = lambda: CHECK_WINDOW.end
    runner = mde_runner.DefenderQueryRunner()
    tenant = _tenant()
    for text in CHECKS:
        runner.check(_request(text, CHECK_WINDOW, 100), tenant)


def fixture(path: str) -> None:
    rule = _rule()
    created = _body(rule)
    service = mde.DefenderForEndpointService.__new__(mde.DefenderForEndpointService)
    safer = _body(service._safer_configuation(_rule()))
    document = {
        "deploy": {"rule": created, "safer": safer},
        "query": {
            "window": [WINDOW.start.isoformat(), WINDOW.end.isoformat()],
            "queries": QUERIES,
        },
        "validate": {
            "window": [CHECK_WINDOW.start.isoformat(), CHECK_WINDOW.end.isoformat()],
            "queries": CHECKS,
        },
    }
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        json.dump(document, out, indent=2)
        out.write("\n")


def main() -> int:
    scenario = sys.argv[1]
    if scenario == "fixture":
        fixture(sys.argv[2])
    else:
        {"deploy": deploy, "query": query, "validate": validate}[scenario]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
