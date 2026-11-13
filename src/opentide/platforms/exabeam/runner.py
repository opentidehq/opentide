"""Run an Exabeam Query Language search on an Exabeam tenant (exabeam-1.0, Query validation).

``opentide query`` sends the query as the ``filter`` of ``POST
/search/v2/events``, with ``fields: ["*"]`` unless the query selects columns,
the run's time range and a ``limit`` of at most 3,000 rows (the most the API
returns). The search is synchronous and has no job id: a runner that stops
waiting closes the connection, because the API has no cancel. Nothing is
saved on the tenant.

``validate query --live`` asks the same endpoint for one row (:meth:`check`):
a ``200`` is a filter the tenant accepts, a ``400`` one it refuses, and any
other answer an error, never a pass.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, ClassVar

import requests

from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.platforms.exabeam.client import (
    ExabeamApiError,
    ExabeamClient,
    ExabeamTenantError,
    api_error,
)
from opentide.platforms.exabeam.compile import SEARCH_PATH, search_body
from opentide.query.models import (
    LiveCheck,
    QueryRefused,
    QueryRequest,
    QueryResult,
    columns_of,
    flatten,
)
from opentide.query.runner import QueryRunner

ExabeamTenant = ConfigurationModels.Systems.Exabeam.Tenant

#: The most rows one search returns (the API's default ``limit``).
MAX_ROWS = 3000

_SELECT = re.compile(r"^\s*SELECT\s+(?:DISTINCT\s+)?", re.IGNORECASE)
#: Where the column list of a ``SELECT`` ends: the next clause.
_CLAUSE = re.compile(r"\b(?:FROM|WHERE|GROUP-BY|ORDER-BY|LIMIT)\b|\|", re.IGNORECASE)
_ALIAS = re.compile(r"\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", re.IGNORECASE)


def _tenant(tenant: SystemConfig.Tenant) -> Any:
    if not isinstance(tenant, ExabeamTenant):
        raise TypeError(f"expected an Exabeam tenant, got {type(tenant).__qualname__}")
    return tenant


def _split_columns(text: str) -> list[str]:
    """*text* split at the commas outside brackets and strings."""
    columns: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    escaped = False
    for char in text:
        if quote is not None:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "," and depth == 0:
            columns.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    columns.append("".join(current).strip())
    return [column for column in columns if column]


def selected_columns(query: str) -> list[str] | None:
    """The columns a ``SELECT`` names (each by its ``AS`` name when it has one), else ``None``.

    ``SELECT *`` selects every field: ``None``, as a query without ``SELECT``.
    """
    head = _SELECT.match(query)
    if head is None:
        return None
    rest = query[head.end() :]
    end = _CLAUSE.search(rest)
    columns = _split_columns(rest[: end.start()] if end else rest)
    if not columns or columns == ["*"]:
        return None
    named: list[str] = []
    for column in columns:
        alias = _ALIAS.search(column)
        named.append(alias.group(1) if alias else column)
    return named


def _rows(payload: Any) -> tuple[list[dict[str, Any]], int | None]:
    if not isinstance(payload, Mapping):
        return [], None
    rows = [flatten(row) for row in payload.get("rows") or [] if isinstance(row, Mapping)]
    total = payload.get("totalRows")
    return rows, total if isinstance(total, int) and not isinstance(total, bool) else None


class ExabeamQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("exabeam",)

    def _client(self, tenant: SystemConfig.Tenant) -> ExabeamClient:
        from opentide.platforms.transport import tenant_tls_verify

        exabeam = _tenant(tenant)
        setup = exabeam.setup
        return self.client(
            tenant,
            lambda: ExabeamClient(
                setup.url,
                setup.client_id,
                setup.client_secret,
                tenant=exabeam.name,
                verify_ssl=tenant_tls_verify(setup.ssl, platform="exabeam", tenant=exabeam.name),
            ),
        )

    def _search(
        self,
        client: ExabeamClient,
        body: dict[str, Any],
        tenant: SystemConfig.Tenant,
        timeout: float,
    ) -> Any:
        """``POST /search/v2/events``: the answer's JSON, or the reason it has none."""
        from opentide.core.errors import Errors

        try:
            response = client.search(body, timeout=timeout)
        except ExabeamTenantError as exc:
            raise Errors.TenantConnectionError(str(exc)) from exc
        except ExabeamApiError as exc:
            raise QueryRefused(
                f"Exabeam could not run the search on {tenant.name}", detail=exc.detail
            ) from exc
        except requests.RequestException:
            # The search has no cancel: stop waiting by closing the connection.
            client.session.close()
            raise
        if response.status_code == 400:
            raise QueryRefused(
                f"Exabeam refused the query on {tenant.name}",
                detail=api_error(f"POST {SEARCH_PATH}", response).detail,
            )
        if response.status_code != 200:
            raise QueryRefused(
                f"Exabeam answered HTTP {response.status_code} to the search on {tenant.name}",
                detail=api_error(f"POST {SEARCH_PATH}", response).detail,
            )
        try:
            return response.json()
        except ValueError as exc:
            raise QueryRefused(
                f"Exabeam did not answer the search with JSON on {tenant.name}"
            ) from exc

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        client = self._client(tenant)
        limit = min(request.limit + 1, MAX_ROWS)
        body = search_body(
            request.text,
            start=request.window.start,
            end=request.window.end,
            limit=limit,
            fields=selected_columns(request.text),
        )
        rows, total = _rows(self._search(client, body, tenant, request.timeout))
        shown = rows[: request.limit]
        warnings: tuple[str, ...] = ()
        if request.limit >= MAX_ROWS:
            warnings = (f"Exabeam returns at most {MAX_ROWS:,} rows per search",)
        truncated = len(rows) > request.limit or (total is not None and total > len(shown))
        return QueryResult(
            columns=columns_of(shown),
            rows=tuple(shown),
            truncated=truncated,
            warnings=warnings,
            language="exabeam",
        )

    def check(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> LiveCheck:
        """One row over ``request.window``, every field: is the filter one the tenant accepts.

        A ``200`` passes, its row count information only; a ``400`` refuses the
        query with Exabeam's message; any other answer fails the check.
        """
        client = self._client(tenant)
        body = search_body(
            request.text, start=request.window.start, end=request.window.end, limit=1
        )
        rows, _total = _rows(self._search(client, body, tenant, request.timeout))
        return LiveCheck(
            result=QueryResult(columns=columns_of(rows), rows=tuple(rows), language="exabeam")
        )


def declare() -> ExabeamQueryRunner:
    return ExabeamQueryRunner()
