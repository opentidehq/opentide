"""Search HarfangLab EDR telemetry.

HarfangLab has no query language for telemetry: its API filters one source by
fields. A query names the source, then ``field=value`` filters, which the API
applies as given (``process_name=cmd.exe``, ``agent.hostname=WS01``,
``commandline__icontains=whoami``)::

    processes process_name=powershell.exe agent.hostname=WS01
"""

from __future__ import annotations

import shlex
from typing import Any, ClassVar

from opentide.core.time import format_utc_z
from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.query.models import QueryRefused, QueryRequest, QueryResult, columns_of, flatten
from opentide.query.runner import QueryRunner

#: Telemetry sources a query may name, and the API path that serves each.
TELEMETRY_SOURCES: dict[str, str] = {
    "processes": "/api/data/telemetry/Processes/",
    "binary": "/api/data/telemetry/Binary/",
    "network": "/api/data/telemetry/Network/",
    "eventlog": "/api/data/telemetry/FullEventLog/",
    "dns": "/api/data/telemetry/DNSResolution/",
    "windows_authentications": "/api/data/telemetry/authentication/AuthenticationWindows/",
    "linux_authentications": "/api/data/telemetry/authentication/AuthenticationLinux/",
    "macos_authentications": "/api/data/telemetry/authentication/AuthenticationMacos/",
}

#: Filters the runner sets itself from the window and the limit.
_RESERVED = frozenset(
    {"limit", "offset", "@event_create_date__gte", "@event_create_date__lte", "ordering"}
)


class HarfangLabQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("telemetry",)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.platforms.harfanglab.client import HarfangLabService

        if not isinstance(tenant, ConfigurationModels.Systems.HarfangLab.Tenant):
            raise TypeError(f"expected a HarfangLab tenant, got {type(tenant).__qualname__}")
        source, filters = parse_telemetry_query(request.text)
        setup = tenant.setup
        reject_unsubstituted_placeholders(setup.url, setup.api_token, client="HarfangLab")
        service = HarfangLabService(tenant)
        params: dict[str, Any] = {
            **filters,
            "@event_create_date__gte": format_utc_z(request.window.start),
            "@event_create_date__lte": format_utc_z(request.window.end),
            "ordering": "-@event_create_date",
            "limit": request.limit + 1,
            "offset": 0,
        }
        url = setup.url.rstrip("/") + TELEMETRY_SOURCES[source]
        response = service.session.get(url, params=params, timeout=request.timeout)
        if response.status_code != 200:
            raise QueryRefused(
                f"HarfangLab refused the telemetry search on {tenant.name} "
                f"(HTTP {response.status_code})",
                detail=response.text[:500] or None,
            )
        body = response.json()
        results = body.get("results", []) if isinstance(body, dict) else []
        rows = [flatten(item) for item in results or [] if isinstance(item, dict)]
        count = body.get("count") if isinstance(body, dict) else None
        truncated = len(rows) > request.limit or (isinstance(count, int) and count > request.limit)
        return QueryResult(
            columns=columns_of(rows[: request.limit]),
            rows=tuple(rows[: request.limit]),
            truncated=truncated,
            language="telemetry",
        )


def parse_telemetry_query(text: str) -> tuple[str, dict[str, str]]:
    """``(source, filters)`` of ``SOURCE field=value ...``; values may be quoted."""
    try:
        words = shlex.split(text)
    except ValueError as exc:
        raise QueryRefused(f"cannot read the telemetry query: {exc}") from None
    sources = ", ".join(TELEMETRY_SOURCES)
    if not words or words[0].lower() not in TELEMETRY_SOURCES:
        raise QueryRefused(
            "a HarfangLab query starts with a telemetry source",
            detail=f"one of: {sources}; then field=value filters",
        )
    filters: dict[str, str] = {}
    for word in words[1:]:
        field, sep, value = word.partition("=")
        if not sep or not field:
            raise QueryRefused(f"{word!r} is not a field=value filter")
        if field in _RESERVED:
            raise QueryRefused(f"{field} is set from --since, --from, --to and --limit")
        filters[field] = value
    return words[0].lower(), filters


def declare() -> HarfangLabQueryRunner:
    return HarfangLabQueryRunner()
