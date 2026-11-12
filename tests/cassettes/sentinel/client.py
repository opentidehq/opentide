"""The Python Sentinel client, driven through each scenario (UC-4.3).

ARM over requests, azure-identity and azure-monitor-query.

``cargo xtask cassettes record sentinel/<scenario>`` runs this with the oracle's
interpreter (the frozen Python implementation) behind the recording proxy, against
``tenant.py``. ``python client.py fixture <path>`` writes, instead, the inputs the
scenarios give the client (the alert rule, the queries, the windows) for the Rust
connector's tests (``crates/opentide-connectors/tests/sentinel.rs``), which must
send what this sent, byte for byte. Each step's outcome is printed, one JSON line
each, for those tests' expectations.

``ClientSecretCredential`` (MSAL) and azure-core stamp each request with a random
id (``client-request-id``, ``x-ms-client-request-id``): ``uuid.uuid1`` and
``uuid.uuid4`` give, here, the ids of :func:`request_id` in order, as the Rust
test's id source does.

Scenarios:

- ``deploy``: sign in (the tenant's OpenID configuration, then the client
  credentials), create an analytics rule, replace it, list the rules (two pages),
  delete it, delete it again (404).
- ``query``: ``opentide query``'s runner: Log Analytics queries over a fixed window:
  rows past the limit, a partial result, two tables, a syntax error, a missing
  permission.
- ``validate``: ``validate query --live``'s check (a search for one row) of two
  queries.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

COUNTER = {"next": 0}


def request_id(number: int) -> uuid.UUID:
    """The *number*-th request id of a run (from 1)."""
    return uuid.UUID(f"00000000-0000-4000-8000-{number:012x}")


def _next_id(*_: Any, **__: Any) -> uuid.UUID:
    COUNTER["next"] += 1
    return request_id(COUNTER["next"])


uuid.uuid1 = _next_id  # type: ignore[assignment]
uuid.uuid4 = _next_id  # type: ignore[assignment]

from opentide.models.system_config import ConfigurationModels as C  # noqa: E402

from opentide.core.errors import Errors  # noqa: E402
from opentide.platforms.sentinel import runner as sentinel_runner  # noqa: E402
from opentide.platforms.sentinel.client import SentinelApiError, SentinelService  # noqa: E402
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow  # noqa: E402

WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)
CHECK_WINDOW = TimeWindow(
    datetime(2026, 10, 27, 7, 59, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)
QUERIES: list[dict[str, Any]] = [
    {
        "text": (
            "SecurityEvent\n| where EventID == 4688\n| project TimeGenerated, Computer, EventID"
        ),
        "limit": 2,
    },
    {"text": "SecurityEvent // partial\n| take 2", "limit": 100},
    {"text": "SecurityEvent // tables", "limit": 100},
    {"text": "SecurityEvent | whre x", "limit": 100},
    {"text": "// forbidden\nSigninLogs", "limit": 100},
]
CHECKS = [
    "SecurityEvent\n| where EventID == 4688",
    "SigninLogs\n| project TimeGenerated, Computer",
]
RULE_ID = "00000000-0000-4000-8003-000000000001"
RULE: dict[str, Any] = {
    "kind": "Scheduled",
    "properties": {
        "displayName": "Encoded PowerShell — Ünïcode",
        "description": "A process ran PowerShell with an encoded command.",
        "severity": "High",
        "enabled": True,
        "query": 'SecurityEvent\n| where CommandLine has "-enc"',
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT5H",
        "suppressionEnabled": False,
        "tactics": ["Execution"],
        "techniques": ["T1059"],
        "subTechniques": ["T1059.001"],
    },
}


def _tenant() -> Any:
    setup = C.Systems.Sentinel.Tenant.Setup(
        ssl=True,
        resource_group="soc-rg",
        workspace_name="soc workspace",
        workspace_id="11111111-2222-4333-8444-555555555555",
        azure_tenant_id="contoso-tenant-id",
        azure_subscription_id="sub-0001",
        azure_client_id="opentide-app-id",
        azure_client_secret=os.environ.get("AZURE_CLIENT_SECRET", "fixture"),
    )
    return C.Systems.Sentinel.Tenant(name="soc", description="", setup=setup)


def _request(text: str, window: TimeWindow, limit: int) -> QueryRequest:
    return QueryRequest(platform="sentinel", text=text, window=window, limit=limit)


def _print(outcome: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(outcome, ensure_ascii=False, default=str) + "\n")


def deploy() -> None:
    tenant = _tenant()
    client = SentinelService(tenant).connect()
    rules = client.alert_rules
    setup = tenant.setup
    for label in ("create", "replace"):
        answer = rules.create_or_update(setup.resource_group, setup.workspace_name, RULE_ID, RULE)
        _print({"step": label, "name": answer.get("name")})
    listed = [item.get("name") for item in rules.list(setup.resource_group, setup.workspace_name)]
    _print({"step": "list", "names": listed})
    rules.delete(setup.resource_group, setup.workspace_name, RULE_ID)
    _print({"step": "delete"})
    try:
        rules.delete(setup.resource_group, setup.workspace_name, RULE_ID)
    except SentinelApiError as error:
        _print({"step": "delete-missing", "error": str(error), "status": error.status_code})


def query() -> None:
    runner = sentinel_runner.SentinelQueryRunner()
    tenant = _tenant()
    for item in QUERIES:
        try:
            result = runner.run(_request(item["text"], WINDOW, item["limit"]), tenant)
        except (QueryRefused, Errors.TenantConnectionError) as error:
            _print(
                {
                    "error": type(error).__name__,
                    "message": str(error),
                    "detail": getattr(error, "detail", None),
                }
            )
            continue
        _print(
            {
                "columns": [[column.name, column.type] for column in result.columns],
                "rows": list(result.rows),
                "truncated": result.truncated,
                "partial": result.partial,
                "warnings": list(result.warnings),
                "sent": result.sent,
            }
        )


def validate() -> None:
    runner = sentinel_runner.SentinelQueryRunner()
    tenant = _tenant()
    for text in CHECKS:
        found = runner.check(_request(text, CHECK_WINDOW, 100), tenant)
        _print({"rows": len(found.result.rows), "sent": found.result.sent})


def fixture(path: str) -> None:
    document = {
        "deploy": {"rule_id": RULE_ID, "rule": RULE},
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
        json.dump(document, out, indent=2, ensure_ascii=False)
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
