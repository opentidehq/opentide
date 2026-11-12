"""Run a YARA-L search on a Google SecOps instance (google-secops-1.0, Query).

``opentide query --platform google_secops`` sends the text to the Chronicle
API v1 ``udmSearch`` with ``queryDialect=YL2``: a read-only search that saves
nothing. A filter search returns UDM events; a search with ``match`` or
``outcome`` returns statistics, one column per grouped or computed value.
``moreDataAvailable`` or ``stats.tooManyResults`` marks the result truncated.
``--rule`` is not supported: a rule runs in the detection engine, whose
results differ from a search's, and a retrohunt writes detections.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from opentide.core.errors import Errors
from opentide.core.time import format_utc_z
from opentide.models.system_config import SystemConfig
from opentide.platforms.google_secops.client import (
    GoogleSecopsApiError,
    GoogleSecopsClient,
    GoogleSecopsTenantError,
)
from opentide.query.models import (
    QueryColumn,
    QueryRefused,
    QueryRequest,
    QueryResult,
    columns_of,
    flatten,
)
from opentide.query.runner import QueryRunner

#: ``udmSearch`` returns at most this many events; Google coerces a larger limit to it.
MAX_UDM_LIMIT = 10_000
TRUNCATED = "the search matched more than it returned: narrow the window or the query"


class GoogleSecopsQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("yaral",)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        client = self.secops_client(tenant, timeout=request.timeout)
        params = {
            "query": request.text.strip(),
            "queryDialect": "YL2",
            "timeRange.startTime": format_utc_z(request.window.start),
            "timeRange.endTime": format_utc_z(request.window.end),
            "limit": str(min(request.limit + 1, MAX_UDM_LIMIT)),
        }
        try:
            answer = client.udm_search(params)
        except GoogleSecopsTenantError as exc:
            raise Errors.TenantConnectionError(exc.message) from exc
        except GoogleSecopsApiError as exc:
            raise QueryRefused(
                f"Google SecOps refused the search on {tenant.name} "
                f"({exc.status or f'HTTP {exc.http_status}'})",
                detail=exc.message or None,
            ) from exc
        return search_result(answer, request.limit)

    def secops_client(self, tenant: SystemConfig.Tenant, *, timeout: float) -> GoogleSecopsClient:
        """*tenant*'s client, made once per runner and timeout."""
        return self.client(
            tenant,
            lambda: GoogleSecopsClient.for_tenant(tenant, timeout=timeout),
            key=f"{timeout:g}",
        )


def _value(cell: Any) -> Any:
    """A stats cell (``{"value": {"int64Val": "5"}}``, ``{"list": {...}}``) as a plain value."""
    if not isinstance(cell, Mapping):
        return cell
    if "value" in cell and isinstance(cell["value"], Mapping):
        inner = cell["value"]
        if not inner:
            return None
        return next(iter(inner.values()))
    if "list" in cell and isinstance(cell["list"], Mapping):
        return [_value(item) for item in cell["list"].get("values") or []]
    if len(cell) == 1:
        return next(iter(cell.values()))
    return dict(cell)


def _stats_rows(stats: Mapping[str, Any]) -> tuple[tuple[QueryColumn, ...], list[dict[str, Any]]]:
    results = [item for item in stats.get("results") or [] if isinstance(item, Mapping)]
    columns = tuple(
        QueryColumn(str(item.get("column") or f"column_{i}")) for i, item in enumerate(results)
    )
    cells: list[Sequence[Any]] = [list(item.get("values") or []) for item in results]
    count = max((len(values) for values in cells), default=0)
    rows = [
        {
            column.name: _value(values[index]) if index < len(values) else None
            for column, values in zip(columns, cells, strict=True)
        }
        for index in range(count)
    ]
    return columns, rows


def search_result(answer: Mapping[str, Any], limit: int) -> QueryResult:
    """A ``udmSearch`` answer as rows: its events, or its statistics."""
    warnings: list[str] = []
    stats = answer.get("stats")
    if isinstance(stats, Mapping) and stats.get("results"):
        columns, rows = _stats_rows(stats)
        truncated = bool(stats.get("tooManyResults")) or len(rows) > limit
    else:
        raw = answer.get("events")
        if isinstance(raw, Mapping):  # {"events": {"events": [...]}}
            raw = raw.get("events")
        events = [item for item in raw or [] if isinstance(item, Mapping)]
        rows = [flatten(_event(item)) for item in events]
        columns = columns_of(rows[:limit])
        truncated = bool(answer.get("moreDataAvailable")) or len(rows) > limit
    if truncated:
        warnings.append(TRUNCATED)
    return QueryResult(
        columns=columns,
        rows=tuple(rows[:limit]),
        truncated=truncated,
        warnings=tuple(warnings),
        language="yaral",
    )


def _event(item: Mapping[str, Any]) -> Mapping[str, Any]:
    """An ``events[]`` entry's UDM event (``{"name": …, "udm": {…}}``)."""
    udm = item.get("udm")
    return udm if isinstance(udm, Mapping) else item


def declare() -> GoogleSecopsQueryRunner:
    return GoogleSecopsQueryRunner()
