"""The CrowdStrike scenarios' client: the Python implementation, as deploy and query run it.

``deploy``: the deployer's client (``CrowdstrikeService``): authenticate, create
a correlation rule, update it, disable it, delete it, then a create and a
delete the tenant refuses. ``query``: the CQL runner (``CrowdstrikeQueryRunner``)
on four searches: one polled until done and cut to its limit, one whose query
has its own ``head``, one that outlives its timeout and is stopped (DELETE),
one the tenant cancels (stopped too), and one refused with HTTP 403. Each
outcome is printed, one JSON line each, for the Rust tests' expectations
(``crates/opentide-connectors/tests/crowdstrike.rs``). Recorded by ``cargo
xtask cassettes record``; the oracle's own modules, unpatched.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from opentide.models.system_config import ConfigurationModels as C

from opentide.platforms.crowdstrike.client import CrowdstrikeService, DetectionRule
from opentide.query.models import QueryRefused, QueryRequest, QueryTimedOut, TimeWindow

WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, 0, 250000, tzinfo=timezone.utc),
)


def tenant() -> Any:
    setup = C.Systems.Crowdstrike.Tenant.Setup(
        ssl=True,
        api="EU-1",
        client_id="opentide-client",
        client_secret=os.environ["CROWDSTRIKE_CLIENT_SECRET"],
        customer_id="0123456789ABCDEF-12",
    )
    return C.Systems.Crowdstrike.Tenant(name="falcon", description="", setup=setup)


def rule(name: str, status: str = "active") -> DetectionRule:
    return DetectionRule(
        name=name,
        description='Encoded PowerShell — Ünïcode "quoted"',
        customer_id="0123456789abcdef",
        severity=70,
        search=DetectionRule.Search(
            outcome="detection",
            filter="#event_simpleName=ProcessRollup2 CommandLine=/-enc/i\n| groupBy([aid])",
            lookback="1h0m",
            trigger_mode="summary",
        ),
        operation=DetectionRule.Operation(
            schedule=DetectionRule.Operation.Schedule(definition="@every 1h0m"),
            start_on="2025-04-15T19:00:00Z",
        ),
        status=status,
        tactic="TA0002",
        technique=None,
        comment="Updated by opentide Crowdstrike Deployer - Author(s) : Amine, Zoé",
    )


def emit(outcome: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(outcome, ensure_ascii=False) + "\n")


def deploy() -> None:
    service = CrowdstrikeService(tenant())
    remote = service.create_detection_rule(rule("Encoded PowerShell"))
    emit({"created": remote})
    service.update_detection_rule(remote, rule("Encoded PowerShell (tuned)"))
    service.update_detection_rule(remote, rule("Encoded PowerShell (tuned)", "inactive"))
    service.delete_detection_rule(remote)
    emit({"deleted": remote})
    for action in (
        lambda: service.create_detection_rule(rule("Rejected rule")),
        lambda: service.update_detection_rule(remote, rule("Rejected rule")),
        lambda: service.delete_detection_rule("cs-rule-missing"),
    ):
        try:
            action()
        except Exception as error:
            emit({"error": type(error).__name__, "message": str(error)})


def query() -> None:
    from opentide.platforms.crowdstrike.runner import CrowdstrikeQueryRunner

    runner = CrowdstrikeQueryRunner()
    for text, kwargs in (
        ("#event_simpleName=ProcessRollup2", {"limit": 1}),
        ("  #event_simpleName=DnsRequest | head(limit=5)  ", {"index": ("investigate_view",)}),
        ("x", {"index": ("slow_view",), "timeout": 0.0}),
        ("x", {"index": ("cancelled_view",)}),
        ("x", {"index": ("forbidden_view",)}),
        ("x", {"index": ("a", "b")}),
    ):
        request = QueryRequest(platform="crowdstrike", text=text, window=WINDOW, **kwargs)
        try:
            result = runner.run(request, tenant())
        except QueryTimedOut as error:
            emit({"timed_out": error.message, "detail": error.detail})
            continue
        except QueryRefused as error:
            emit({"refused": error.message, "detail": error.detail})
            continue
        emit(
            {
                "columns": [column.name for column in result.columns],
                "rows": list(result.rows),
                "truncated": result.truncated,
                "warnings": list(result.warnings),
                "vendor_query_id": result.vendor_query_id,
                "sent": result.sent,
                "language": result.language,
            }
        )


if __name__ == "__main__":
    {"deploy": deploy, "query": query}[sys.argv[1]]()
