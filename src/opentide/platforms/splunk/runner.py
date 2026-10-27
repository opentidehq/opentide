"""Run an SPL search on a Splunk tenant as a one-shot job, which keeps no saved search."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from opentide.core.time import format_utc_z
from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.query.models import QueryColumn, QueryRefused, QueryRequest, QueryResult
from opentide.query.runner import QueryRunner


class SplunkQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("spl",)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from splunklib.binding import HTTPError

        from opentide.platforms.splunk.client import connect_splunk

        if not isinstance(tenant, ConfigurationModels.Systems.Splunk.Tenant):
            raise TypeError(f"expected a Splunk tenant, got {type(tenant).__qualname__}")
        setup = tenant.setup
        service = connect_splunk(
            host=setup.url,
            port=setup.port,
            token=setup.token,
            app=setup.app,
            ssl_enabled=setup.ssl,
        )
        sent = spl_search(request.text)
        try:
            stream = service.jobs.oneshot(
                sent,
                earliest_time=format_utc_z(request.window.start),
                latest_time=format_utc_z(request.window.end),
                count=request.limit + 1,
                output_mode="json",
            )
            body = _parse(stream.read())
        except HTTPError as exc:
            raise QueryRefused(
                f"Splunk refused the search on {tenant.name} (HTTP {exc.status})",
                detail=_messages(_parse(exc.body), ("ERROR", "FATAL")) or str(exc),
            ) from exc
        errors = _messages(body, ("ERROR", "FATAL"))
        if errors:
            raise QueryRefused(f"Splunk refused the search on {tenant.name}", detail=errors)
        rows = [row for row in body.get("results", []) or [] if isinstance(row, dict)]
        fields = [field.get("name") for field in body.get("fields", []) or []]
        names = [str(name) for name in fields if isinstance(name, str)]
        if not names:
            names = list(dict.fromkeys(key for row in rows for key in row))
        # Splunk's own warnings: a missing index, a truncated lookup.
        warning = _messages(body, ("WARN",))
        warnings = (warning,) if warning else ()
        return QueryResult(
            columns=tuple(QueryColumn(name) for name in names),
            rows=tuple(rows[: request.limit]),
            truncated=len(rows) > request.limit,
            warnings=warnings,
            sent=sent if sent != request.text.strip() else None,
            language="spl",
        )


def spl_search(query: str) -> str:
    """*query* as Splunk runs it: a query that does not start with a command searches."""
    text = query.strip()
    if text.startswith("|") or text.lower().startswith("search "):
        return text
    return f"search {text}"


def _parse(raw: Any) -> dict[str, Any]:
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {"messages": [{"type": "ERROR", "text": str(raw)}]}
    return parsed if isinstance(parsed, dict) else {}


def _messages(body: dict[str, Any], kinds: tuple[str, ...]) -> str:
    texts = [
        str(message.get("text", ""))
        for message in body.get("messages", []) or []
        if isinstance(message, dict) and str(message.get("type", "")).upper() in kinds
    ]
    return "; ".join(text for text in texts if text)


def declare() -> SplunkQueryRunner:
    return SplunkQueryRunner()
