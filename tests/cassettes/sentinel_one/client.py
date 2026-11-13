"""The Python SentinelOne client, driven through each scenario (UC-4.2).

``cargo xtask cassettes record sentinel_one/<scenario>`` runs this with the oracle's
interpreter (the frozen Python implementation) behind the recording proxy, against
``tenant.py``. ``python client.py fixture <path>`` writes, instead, the inputs the
scenarios give the client (each STAR rule's body, the queries) for the Rust
connector's tests (``crates/opentide-connectors/tests/sentinel_one.rs``), which must
send what this sent, byte for byte.

Scenarios:

- ``deploy``: a correlation rule and a single-event rule compiled by
  ``SentinelOneDeploy.compile_deployment``, created; the first updated, then an
  update of an id the console does not hold (404); the first disabled, then deleted;
  then ``validate_query`` on a query that runs and one the API refuses.
- ``query``: ``opentide query``'s runner: a PowerQuery polled until it finishes, one
  that finishes at once, one the API refuses (400), one that ends FAILED.
- ``validate``: ``validate query --live``'s check (one row over the last minute) of
  a rule's queries.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from opentide.core.errors import Errors
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels as C
from opentide.platforms.sentinel_one import client as s1_client
from opentide.platforms.sentinel_one import runner as s1_runner
from opentide.platforms.sentinel_one.client import SentinelOneService
from opentide.platforms.sentinel_one.deployer import SentinelOneDeploy
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow

WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)
CHECK_WINDOW = TimeWindow(
    datetime(2026, 10, 27, 7, 59, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)
QUERIES: list[dict[str, Any]] = [
    {"text": 'event.type = "Process Creation" // slow', "limit": 1},
    {"text": "src.process.name contains 'cmd' | limit 5", "limit": 100},
    {"text": "event.type = 'x' | syntax", "limit": 100},
    {"text": "event.type = 'y' // fails", "limit": 100},
]
CHECKS = ['EventType = "Process Create"', "src.process.name = 'cmd.exe'"]
VALIDATIONS = ['EventType = "Process Create"', "EventType = | syntax"]


def _tenant() -> Any:
    setup = C.Systems.SentinelOne.Tenant.Setup(
        ssl=True,
        url="https://s1.invalid",
        account_id=4242,
        api_token=os.environ.get("S1_API_TOKEN", "fixture"),
        site_id=77,
    )
    return C.Systems.SentinelOne.Tenant(name="s1", description="", setup=setup)


def _rule(suffix: str, condition: dict[str, Any], **extra: Any) -> Any:
    raw = {
        "name": f"SentinelOne rule {suffix} — Ünïcode",
        "metadata": {
            "uuid": f"00000000-0000-4000-8003-0000000000{suffix}",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "tlp": "clear",
        },
        "description": f"Rule {suffix} of the SentinelOne connector's cassettes.",
        "techniques": [],
        "response": {"alert_severity": "High"},
        "configurations": {
            "sentinel_one": {
                "enabled": True,
                "status": "STAGING",
                "condition": condition,
                **extra,
            }
        },
    }
    return load_rule_from_dict(raw)


def rules() -> list[Any]:
    return [
        _rule(
            "41",
            {
                "type": "Correlation",
                "correlation": {
                    "entity": "host",
                    "match_in_order": True,
                    "time_window": "1h",
                    "sub_queries": [
                        {"query": 'EventType = "Process Create"', "matches_required": 1},
                        {"query": "src.process.name = 'cmd.exe'", "matches_required": 2},
                    ],
                },
                "cool_off": "30m",
            },
            response={"treat_as_threat": "Malicious", "network_quarantine": False},
        ),
        _rule(
            "42",
            {
                "type": "Single Event",
                "single_event": {"query": "src.process.name = 'cmd.exe'"},
            },
            response={"treat_as_threat": False, "network_quarantine": True},
        ),
    ]


def _api_rules() -> list[Any]:
    tenant = _tenant()
    return [SentinelOneDeploy().compile_deployment(rule, tenant) for rule in rules()]


def _without_nulls(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _without_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_without_nulls(item) for item in value if item is not None]
    return value


def deploy() -> None:
    # validate_query's window is the minute before now: a fixed now.
    s1_client.utc_now = lambda: CHECK_WINDOW.end
    service = SentinelOneService(_tenant())
    correlation, single = _api_rules()
    first = service.create_update_detection_rule(correlation)
    service.create_update_detection_rule(single)
    service.create_update_detection_rule(correlation, first)
    with contextlib.suppress(Errors.DetectionRuleCreationFailed):
        service.create_update_detection_rule(correlation, 999)
    service.disable_detection_rule(first)
    service.delete_detection_rule(first)
    for query in VALIDATIONS:
        service.validate_query(query)


def _request(text: str, window: TimeWindow, limit: int) -> QueryRequest:
    return QueryRequest(platform="sentinel_one", text=text, window=window, limit=limit)


def query() -> None:
    s1_runner.sleep = lambda seconds: None
    runner = s1_runner.SentinelOneQueryRunner()
    tenant = _tenant()
    for item in QUERIES:
        with contextlib.suppress(QueryRefused):
            runner.run(_request(item["text"], WINDOW, item["limit"]), tenant)


def validate() -> None:
    runner = s1_runner.SentinelOneQueryRunner()
    tenant = _tenant()
    for text in CHECKS:
        runner.check(_request(text, CHECK_WINDOW, 100), tenant)


def fixture(path: str) -> None:
    document = {
        "deploy": {
            "rules": [_without_nulls(asdict(rule)) for rule in _api_rules()],
            "validations": VALIDATIONS,
        },
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
