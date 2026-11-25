"""The Graylog scenarios' client: the Python implementation, as deploy and query run it.

``deploy``: the deployer's client (``GraylogClient``) on the 7.2 tenant and on
the 6.3 one — the version, the query check, a create, an update, a disable
(``?schedule=false``) and a delete, then the refusals of the specification's
failure table: a create Graylog answers with a page (unconfirmed), one it
refuses with ``errors``, an update of a definition it does not hold (404), an
immutable definition and a delete of one in use. ``query``: the message search
(``GraylogQueryRunner``), on 7.2 (every field) and on 6.3 (only the fields the
query names). ``validate``: the live check (``POST /api/search/validate``) with
an OK verdict, a warning and a refusal.

Each outcome is printed, one JSON line each, for the Rust tests' expectations
(``crates/opentide-connectors/tests/graylog.rs``). Recorded by ``cargo xtask
cassettes record``, with the oracle's own modules: the recording needs the
0.28.0 oracle, since 0.23.0 has no Graylog platform.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from opentide.models.system_config import ConfigurationModels as C
from opentide.platforms.graylog.client import GraylogApiError, GraylogClient, read_verdict
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow

#: The window every recorded search covers.
WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, 0, 250000, tzinfo=timezone.utc),
)
#: The stand-in's streams and the id it hands the first definition.
STREAM_ID = "65f0c0ffee0123456789abcd"
NOTIFICATION_ID = "65f0c0ffee0123456789abcf"
DEFINITION_ID = "65f1c0de2a3b4c5d6e7f8091"
#: Ids the stand-in refuses, by the failure they stand for.
IMMUTABLE_ID = "65f1c0de2a3b4c5d6e7ff0ff"
IN_USE_ID = "65f1c0de2a3b4c5d6einuse"
MISSING_ID = "65f1c0de2a3b4c5d6e7f0000"

#: The two tenants of the scenarios: 7.2 and 6.3.
TENANTS = (("graylog-prod", "graylog-tenant.invalid"), ("graylog-old", "graylog-63.invalid"))

QUERY = "EventID:1 AND image_lc:/.*\\\\powershell\\.exe/"
WARNING_QUERY = "EventID:1 AND unknown_field:x"
BROKEN_QUERY = "EventID:1 AND ("
#: The definition's title on both tenants.
TITLE = "Office application spawns obfuscated PowerShell"


def tenant(name: str, host: str) -> Any:
    setup = C.Systems.Graylog.Tenant.Setup(
        ssl=True,
        url=f"https://{host}/",
        token=os.environ["GRAYLOG_TOKEN"],
        allow_leading_wildcard=False,
        streams=["sysmon"],
        stream_ids={"sysmon": STREAM_ID},
        notification_ids={"soc-slack": NOTIFICATION_ID},
        tags=["managed-by-opentide"],
    )
    return C.Systems.Graylog.Tenant(name=name, description="", setup=setup)


def client(name: str, host: str) -> GraylogClient:
    graylog = tenant(name, host)
    return GraylogClient(
        graylog.setup.url,
        graylog.setup.token,
        tenant=graylog.name,
        verify_ssl=True,
    )


def definition(title: str, *, aggregation: bool = True) -> dict[str, Any]:
    """An event definition as ``compile_definition`` builds one, for 7.2."""
    config: dict[str, Any] = {
        "type": "aggregation-v1",
        "query": QUERY,
        "query_parameters": [],
        "filters": [],
        "streams": [STREAM_ID],
        "stream_categories": [],
        "group_by": ["source"] if aggregation else [],
        "series": [{"id": "count-", "type": "count"}] if aggregation else [],
        "conditions": {
            "expression": {
                "expr": ">=",
                "left": {"expr": "number-ref", "ref": "count-"},
                "right": {"expr": "number", "value": 3},
            }
        }
        if aggregation
        else {"expression": None},
        "search_within_ms": 900000,
        "execute_every_ms": 300000,
        "use_cron_scheduling": False,
    }
    if not aggregation:
        config["event_limit"] = 100
    return {
        "_scope": "DEFAULT",
        "title": title,
        "description": "An Office application started PowerShell with an encoded command.",
        "priority": 3,
        "alert": True,
        "tags": ["opentide", "managed-by-opentide"],
        "tactics_techniques": ["T1059.001", "TA0002"],
        "config": config,
        "field_spec": {},
        "key_spec": [],
        "notification_settings": {"grace_period_ms": 0, "backlog_size": 0},
        "notifications": [{"notification_id": NOTIFICATION_ID}],
    }


def validate_body(query: str) -> dict[str, Any]:
    return {
        "query": query,
        "streams": [STREAM_ID],
        "stream_categories": [],
        "timerange": {"type": "relative", "range": 900},
    }


def emit(outcome: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(outcome, ensure_ascii=False) + "\n")


def attempt(action: Any) -> None:
    try:
        answer = action()
    except GraylogApiError as error:
        emit(
            {
                "error": "GraylogApiError",
                "status": error.status,
                "code": failure_code(error),
                "detail": error.detail,
            }
        )
    except Exception as error:  # a refused token, a version, no answer
        emit({"error": type(error).__name__, "message": str(error)})
    else:
        emit({"ok": True, "answer": answer})


def failure_code(error: GraylogApiError) -> str:
    """The code the specification's failure table gives this answer."""
    if error.immutable:
        return "graylog_definition_immutable"
    if error.in_use:
        return "graylog_definition_in_use"
    if error.forbidden:
        return "graylog_forbidden"
    if error.invalid:
        return "graylog_definition_invalid"
    if error.not_found:
        return "graylog_definition_missing"
    return "graylog_request_failed"


def deploy() -> None:
    """Every write of a deploy, on 7.2 and on 6.3, then the failure table."""
    for name, host in TENANTS:
        api = client(name, host)
        emit({"version": list(api.version())})
        verdict = api.validate_query(validate_body(QUERY))
        errors, warnings = read_verdict(verdict)
        emit({"verdict": {"errors": errors, "warnings": warnings}})
        wrapped = (
            {**definition(TITLE), "share_request": None}
            if api.version() < (7, 0, 0)
            else {"entity": definition(TITLE), "share_request": None}
        )
        attempt(lambda api=api, body=wrapped: api.create(body))
        attempt(
            lambda api=api: api.update(
                DEFINITION_ID,
                {**definition(TITLE), "id": DEFINITION_ID},
                enabled=True,
            )
        )
        attempt(
            lambda api=api: api.update(
                DEFINITION_ID,
                {**definition(TITLE), "id": DEFINITION_ID},
                enabled=False,
            )
        )
        attempt(lambda api=api: api.delete(DEFINITION_ID))
    api = client("graylog-prod", "graylog-tenant.invalid")
    # The failure table: an unconfirmed create, a refused one, a definition
    # Graylog does not hold, an immutable one, and one in use.
    attempt(lambda: api.create({"entity": definition("Unconfirmed create"), "share_request": None}))
    attempt(lambda: api.create({"entity": definition("Refused create"), "share_request": None}))
    attempt(
        lambda: api.update(
            MISSING_ID, {**definition("Missing definition"), "id": MISSING_ID}, enabled=True
        )
    )
    attempt(
        lambda: api.update(
            IMMUTABLE_ID, {**definition("Immutable definition"), "id": IMMUTABLE_ID}, enabled=True
        )
    )
    attempt(lambda: api.delete(IN_USE_ID))
    # A query Graylog refuses: nothing is saved.
    verdict = api.validate_query(validate_body(BROKEN_QUERY))
    errors, warnings = read_verdict(verdict)
    emit({"verdict": {"errors": errors, "warnings": warnings}})


def query() -> None:
    """The message search on 7.2 (every field) and on 6.3 (the query's fields)."""
    from opentide.platforms.graylog.runner import GraylogQueryRunner

    runner = GraylogQueryRunner()
    for name, host in TENANTS:
        request = QueryRequest(platform="graylog", text=QUERY, window=WINDOW, limit=1)
        try:
            result = runner.run(request, tenant(name, host))
        except QueryRefused as error:
            emit({"refused": error.message, "detail": error.detail})
            continue
        emit(
            {
                "columns": [column.name for column in result.columns],
                "rows": list(result.rows),
                "truncated": result.truncated,
                "language": result.language,
            }
        )


def validate() -> None:
    """The live check: an OK verdict, a warning, and a refusal."""
    from opentide.platforms.graylog.runner import GraylogQueryRunner

    runner = GraylogQueryRunner()
    graylog = tenant("graylog-prod", "graylog-tenant.invalid")
    for text in (QUERY, WARNING_QUERY, BROKEN_QUERY):
        request = QueryRequest(platform="graylog", text=text, window=WINDOW, limit=1)
        try:
            check = runner.check(request, graylog)
        except QueryRefused as error:
            emit({"refused": error.message, "detail": error.detail})
            continue
        emit({"warnings": list(check.warnings)})


if __name__ == "__main__":
    {"deploy": deploy, "query": query, "validate": validate}[sys.argv[1]]()
