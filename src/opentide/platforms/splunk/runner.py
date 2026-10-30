"""Run an SPL search on a Splunk tenant as a one-shot job, which keeps no saved search."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar

import structlog

from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.query.models import LiveCheck, QueryColumn, QueryRefused, QueryRequest, QueryResult
from opentide.query.runner import QueryRunner

if TYPE_CHECKING:
    from splunklib.client import Service

logger = structlog.get_logger(__name__)

#: The warning a parse that timed out at a gateway carries: the query is assumed valid.
PARSER_TIMEOUT_WARNING = "Splunk's parser timed out behind a gateway; the query is assumed valid"


class SplunkQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("spl",)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from splunklib.binding import HTTPError

        service = self._service(tenant)
        sent = spl_search(request.text)
        try:
            stream = service.jobs.oneshot(
                sent,
                # Epoch seconds: Splunk reads them whatever the server's time_format.
                earliest_time=f"{request.window.start.timestamp():.3f}",
                latest_time=f"{request.window.end.timestamp():.3f}",
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

    def check(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> LiveCheck:
        """Splunk's ``search/parser``: the query is parsed with its macros and lookups, no
        search job runs."""
        from opentide.platforms.splunk.client import HTTP_ERROR_STATUS

        service = self._service(tenant, allow_http_errors=True)
        query = request.text.strip()
        if not query.startswith("| "):
            query = "| search " + query
        response = service.parse(
            query.strip(), enable_lookups=True, output_mode="json", reload_macros=True
        )
        status = response["status"]
        if status == HTTP_ERROR_STATUS:
            # The body is a stream: read it once. A second read returned b"" and
            # failed in json.loads, so a refused query on a redirect crashed the
            # check instead of being reported.
            body = response["body"].read()
            if response.get("reason") == "Temporary Redirect" and "Network Error" in str(body):
                return LiveCheck(warnings=(PARSER_TIMEOUT_WARNING,))
            messages = _parse(body).get("messages", []) or []
            texts = [str(m.get("text", "")) for m in messages if isinstance(m, dict)]
            detail = "; ".join(text for text in texts if text) or None
            raise QueryRefused(f"Splunk refused the query on {tenant.name}", detail=detail)
        if status != 200:
            # Neither a refusal nor an acceptance: reported, and not failed (as before #673).
            logger.critical("unexpected_splunk_validation_response", response=str(response))
        return LiveCheck()

    def _service(self, tenant: SystemConfig.Tenant, *, allow_http_errors: bool = False) -> Service:
        from opentide.platforms.splunk.client import connect_splunk

        if not isinstance(tenant, ConfigurationModels.Systems.Splunk.Tenant):
            raise TypeError(f"expected a Splunk tenant, got {type(tenant).__qualname__}")
        setup = tenant.setup
        return self.client(
            tenant,
            lambda: connect_splunk(
                host=setup.url,
                port=setup.port,
                token=setup.token,
                app=setup.app,
                allow_http_errors=allow_http_errors,
                ssl_enabled=setup.ssl,
            ),
            key="parser" if allow_http_errors else "",
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
