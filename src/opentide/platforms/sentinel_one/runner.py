"""Run a PowerQuery on a SentinelOne tenant: submit it, then poll until it finishes."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any, ClassVar

import requests

from opentide.core.time import format_utc_z
from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.query.models import QueryColumn, QueryRefused, QueryRequest, QueryResult
from opentide.query.runner import QueryRunner

#: Replaced in tests, so polling costs no wall-clock time.
sleep: Callable[[float], None] = time.sleep

_LIMIT_STAGE = re.compile(r"\|\s*limit\s+\d+", re.IGNORECASE)


class SentinelOneQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("powerquery",)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.platforms.sentinel_one.client import SentinelOneService

        if not isinstance(tenant, ConfigurationModels.Systems.SentinelOne.Tenant):
            raise TypeError(f"expected a SentinelOne tenant, got {type(tenant).__qualname__}")
        setup = tenant.setup
        reject_unsubstituted_placeholders(setup.url, setup.api_token, client="SentinelOne")
        service = self.client(tenant, lambda: SentinelOneService(tenant))
        sent = powerquery_with_limit(request.text, request.limit)
        body: dict[str, Any] = {
            "query": sent,
            "fromDate": format_utc_z(request.window.start),
            "toDate": format_utc_z(request.window.end),
            "limit": request.limit + 1,
            "accountIds": [str(setup.account_id)],
        }
        if setup.site_id:
            body["siteIds"] = [str(setup.site_id)]
        response = service.session.post(service.CREATE_QUERY_ENDPOINT, json=body)
        data = _data(response, tenant.name)
        query_id = str(data.get("queryId") or "") or None
        ping = service.CREATE_QUERY_ENDPOINT.removesuffix("/pq") + "/pq-ping"
        deadline = time.monotonic() + request.timeout
        delay = 0.5
        while not _finished(data):
            if query_id is None:
                raise QueryRefused(f"SentinelOne returned no query id on {tenant.name}")
            if time.monotonic() >= deadline:
                raise QueryRefused(
                    f"the PowerQuery did not finish within {request.timeout:g}s on {tenant.name}",
                    detail="narrow the window or raise --timeout",
                )
            sleep(delay)
            delay = min(delay * 2, 5.0)
            data = _data(service.session.get(ping, params={"queryId": query_id}), tenant.name)
        names = [_column_name(column) for column in data.get("columns", []) or []]
        rows = [
            dict(zip(names, row, strict=False))
            for row in data.get("data", []) or []
            if isinstance(row, list)
        ]
        warnings = tuple(str(item) for item in data.get("recommendations", []) or [] if item)
        return QueryResult(
            columns=tuple(QueryColumn(name) for name in names),
            rows=tuple(rows[: request.limit]),
            truncated=len(rows) > request.limit,
            warnings=warnings,
            vendor_query_id=query_id,
            sent=sent if sent != request.text.strip() else None,
            language="powerquery",
        )


def powerquery_with_limit(query: str, limit: int) -> str:
    """*query* with ``| limit limit+1`` appended, unless it already has a ``limit`` stage."""
    from opentide.query.runner import kql_code

    text = query.strip()
    # Strings and `//` comments are blanked first: a `| limit` in either is not a stage.
    if _LIMIT_STAGE.search(kql_code(text)):
        return text
    # A line of its own, so a trailing `//` comment cannot swallow it.
    return f"{text}\n| limit {limit + 1}"


def _finished(data: dict[str, Any]) -> bool:
    status = str(data.get("status", "")).upper()
    if status in ("FAILED", "FAILED_CLIENT", "TIMED_OUT", "CANCELLED"):
        raise QueryRefused(
            f"the PowerQuery ended {status.lower()}",
            detail=str(data.get("responseError") or data.get("error") or "") or None,
        )
    return status == "FINISHED"


def _data(response: requests.Response, tenant: str) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        body = {}
    if response.status_code != 200:
        detail = None
        errors = body.get("errors") if isinstance(body, dict) else None
        if isinstance(errors, list) and errors and isinstance(errors[0], dict):
            detail = str(errors[0].get("detail") or errors[0].get("title") or "") or None
        raise QueryRefused(
            f"SentinelOne refused the PowerQuery on {tenant} (HTTP {response.status_code})",
            detail=detail or response.text[:500] or None,
        )
    data = body.get("data") if isinstance(body, dict) else None
    return data if isinstance(data, dict) else {}


def _column_name(column: Any) -> str:
    if isinstance(column, dict):
        return str(column.get("name") or column.get("title") or "")
    return str(column)


def declare() -> SentinelOneQueryRunner:
    return SentinelOneQueryRunner()
