"""The Python Defender for Endpoint client, driven through each scenario (UC-4.2).

``cargo xtask cassettes record defender/<scenario>`` runs this with the oracle's
interpreter (the frozen Python implementation) behind the recording proxy, against
``tenant.py``. ``python client.py fixture <path>`` writes, instead, the inputs the
scenarios give the client (bodies, queries, windows) for the Rust connector's
tests (``crates/opentide-connectors/tests/defender.rs``), which must send what this
sent, byte for byte.

Scenarios:

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
from datetime import datetime, timezone
from typing import Any

from opentide.models.system_config import ConfigurationModels as C
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


def _request(text: str, window: TimeWindow, limit: int) -> QueryRequest:
    return QueryRequest(platform="microsoft_defender", text=text, window=window, limit=limit)


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
    document = {
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
        {"query": query, "validate": validate}[scenario]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
