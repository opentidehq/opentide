"""What ``opentide query`` sends to a tenant and what it brings back."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from opentide.core.time import format_utc_z

#: Rows returned when the caller names no limit (also the MCP ``run_query`` default).
DEFAULT_LIMIT = 100
#: The most rows one query may return per tenant; protects the terminal and the quota.
#: Runners ask for one row more, which must stay under the 10 000-row caps of
#: Elasticsearch's result window and Carbon Black's process search.
MAX_LIMIT = 5_000
#: Seconds an asynchronous platform search (S1, CBC, CrowdStrike) may run.
DEFAULT_TIMEOUT = 120.0


class QueryRefused(Exception):
    """The platform answered and refused the query: syntax, permission, quota, timeout.

    ``detail`` is the vendor's own message when it gave one.
    """

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


@dataclass(frozen=True)
class TimeWindow:
    """A UTC interval, ``start`` inclusive."""

    start: datetime
    end: datetime

    @property
    def seconds(self) -> int:
        return max(1, int((self.end - self.start).total_seconds()))

    def to_dict(self) -> dict[str, str]:
        return {"from": format_utc_z(self.start), "to": format_utc_z(self.end)}


@dataclass(frozen=True)
class QueryRequest:
    """One query for one tenant."""

    platform: str
    text: str
    window: TimeWindow
    limit: int = DEFAULT_LIMIT
    #: The platform's query language when it has several (Elastic); ``None`` takes the default.
    language: str | None = None
    #: Elastic indices or data view, HarfangLab telemetry source, CrowdStrike repository.
    index: tuple[str, ...] = ()
    data_view: str | None = None
    #: Which query of a rule this is, when a rule has several (SentinelOne correlation).
    label: str | None = None
    timeout: float = DEFAULT_TIMEOUT


@dataclass(frozen=True)
class QueryColumn:
    name: str
    #: The vendor's type name, verbatim; ``None`` when the platform reports none.
    type: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {"name": self.name, "type": self.type}


@dataclass(frozen=True)
class QueryResult:
    """The rows one tenant returned for one query."""

    columns: tuple[QueryColumn, ...]
    rows: tuple[dict[str, Any], ...]
    #: More rows matched than ``limit`` let through.
    truncated: bool = False
    #: The platform stopped early (timeout, its own row cap) and says the rows are incomplete.
    partial: bool = False
    warnings: tuple[str, ...] = ()
    #: The platform's id for the search (Splunk sid, S1 queryId, CrowdStrike job id).
    vendor_query_id: str | None = None
    #: What the query actually sent, when the runner changed it (a ``take`` it appended).
    sent: str | None = None
    #: The language the runner used, when the platform has several.
    language: str | None = None


@dataclass(frozen=True)
class LiveCheck:
    """A tenant accepted a query: what ``validate query --live`` learns from one check.

    ``result`` holds the search's answer when the check ran one (its columns
    feed checks such as Defender's required columns); a parse-only check
    (Splunk, Carbon Black) leaves it ``None``. ``warnings`` are the tenant's
    reservations about the verdict, such as a parser that timed out; a refusal
    is raised as :class:`QueryRefused` instead.
    """

    result: QueryResult | None = None
    warnings: tuple[str, ...] = ()


@dataclass
class TenantOutcome:
    """A query's result on one tenant, or why it has none."""

    tenant: str
    label: str | None = None
    result: QueryResult | None = None
    error: str | None = None
    detail: str | None = None
    elapsed_ms: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.result is not None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"tenant": self.tenant, "status": "ok" if self.ok else "failed"}
        if self.label is not None:
            payload["label"] = self.label
        result = self.result
        warnings = list(self.warnings)
        if result is not None:
            warnings.extend(result.warnings)
            payload.update(
                {
                    "columns": [column.to_dict() for column in result.columns],
                    "rows": [json_safe_row(row) for row in result.rows],
                    "row_count": len(result.rows),
                    "truncated": result.truncated,
                    "partial": result.partial,
                }
            )
            if result.language is not None:
                payload["language"] = result.language
            if result.sent is not None:
                payload["sent"] = result.sent
            if result.vendor_query_id is not None:
                payload["vendor_query_id"] = result.vendor_query_id
        else:
            payload["error"] = self.error
            if self.detail:
                payload["detail"] = self.detail
        payload["warnings"] = warnings
        payload["elapsed_ms"] = self.elapsed_ms
        return payload


def json_safe(value: Any) -> Any:
    """*value* as JSON can carry it: datetimes as ISO strings, bytes as base64."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return format_utc_z(value) if value.tzinfo is not None else value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(item) for item in value]
    return str(value)


def json_safe_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): json_safe(value) for key, value in row.items()}


def flatten(document: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Nested objects as dotted keys (``process.name``); lists stay values."""
    flat: dict[str, Any] = {}
    for key, value in document.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping) and value:
            flat.update(flatten(value, f"{name}."))
        else:
            flat[name] = value
    return flat


def columns_of(rows: Sequence[Mapping[str, Any]]) -> tuple[QueryColumn, ...]:
    """The union of the rows' keys, in first-seen order: for platforms that name no schema."""
    names: dict[str, None] = {}
    for row in rows:
        for key in row:
            names.setdefault(str(key), None)
    return tuple(QueryColumn(name) for name in names)
