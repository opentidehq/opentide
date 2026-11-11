"""Run a search on a Graylog tenant (graylog-1.0, Query validation).

``opentide query`` sends ``POST /api/search/messages``, which reads messages
and saves nothing. ``validate query --live`` asks ``POST /api/search/validate``
instead (:meth:`GraylogQueryRunner.check`): Graylog parses the query against
the streams' field mappings, and no search runs.

``request.index`` holds stream aliases from the tenant's ``stream_ids`` table
(or stream ids, 24 hex); none means the tenant's ``streams``.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from opentide.core.time import format_utc_z
from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.platforms.graylog.client import (
    GraylogApiError,
    GraylogClient,
    GraylogTenantError,
    read_verdict,
)
from opentide.platforms.graylog.compile import Version
from opentide.platforms.graylog.constraints import as_list
from opentide.query.models import (
    LiveCheck,
    QueryColumn,
    QueryRefused,
    QueryRequest,
    QueryResult,
)
from opentide.query.runner import QueryRunner

GraylogTenant = ConfigurationModels.Systems.Graylog.Tenant

_STREAM_ID = re.compile(r"[0-9a-f]{24}")
#: A ``field:`` the query names (``_exists_:field`` names one too).
_QUERY_FIELD = re.compile(r"(?<![\w.@\\-])(?:_exists_:)?([A-Za-z0-9_@-]+(?:\.[A-Za-z0-9_@-]+)*):")
#: Fields every search asks for before 7.2, where Graylog returns only the fields it is asked for.
_BASE_FIELDS = ("timestamp", "source", "message")
#: Graylog's placeholder for a field a message does not have.
_MISSING = "-"


def _tenant(tenant: SystemConfig.Tenant) -> ConfigurationModels.Systems.Graylog.Tenant:
    if not isinstance(tenant, GraylogTenant):
        raise TypeError(f"expected a Graylog tenant, got {type(tenant).__qualname__}")
    return tenant


def resolve_streams(aliases: tuple[str, ...], tenant: SystemConfig.Tenant) -> list[str]:
    """Stream ids for *aliases* (or the tenant's ``streams`` when there are none).

    A 24-hex value is a stream id already. Raises :class:`QueryRefused` for an
    alias the tenant does not define.
    """
    setup = _tenant(tenant).setup
    names = list(aliases) or as_list(setup.streams)
    table = dict(setup.stream_ids or {})
    unknown = [name for name in names if name not in table and not _STREAM_ID.fullmatch(name)]
    if unknown:
        raise QueryRefused(
            f"graylog_alias_unknown: stream alias(es) {', '.join(unknown)} are not in tenant "
            f"{tenant.name}'s stream_ids table"
        )
    return [table.get(name, name) for name in names]


def requested_fields(query: str, version: Version) -> list[str] | None:
    """The ``fields`` a search asks for: none on 7.2+, where Graylog returns every field.

    Before 7.2 Graylog returns only the fields it is asked for: the message's
    timestamp, source and message, and the fields the query names. On 6.3 and
    7.0, Graylog splits a requested name on ``.``, so a dotted field is not asked for.
    """
    if version >= (7, 2, 0):
        return None
    fields = list(_BASE_FIELDS)
    for name in _QUERY_FIELD.findall(query):
        if name == "_exists_" or name in fields:
            continue
        if "." in name and version < (7, 1, 0):
            continue
        fields.append(name)
    return fields


def _rows(payload: Any) -> tuple[list[QueryColumn], list[dict[str, Any]]]:
    if not isinstance(payload, dict):
        return [], []
    schema = payload.get("schema") if isinstance(payload.get("schema"), list) else []
    columns = [
        QueryColumn(str(entry.get("field") or entry.get("name")), entry.get("type"))
        for entry in schema
        if isinstance(entry, dict)
    ]
    rows: list[dict[str, Any]] = []
    for datarow in payload.get("datarows") or []:
        if not isinstance(datarow, list):
            continue
        rows.append(
            {
                column.name: value
                for column, value in zip(columns, datarow, strict=False)
                if value is not None and value != _MISSING
            }
        )
    return columns, rows


class GraylogQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("lucene",)

    def _client(self, tenant: SystemConfig.Tenant, timeout: float) -> GraylogClient:
        from opentide.platforms.transport import tenant_tls_verify

        graylog = _tenant(tenant)
        setup = graylog.setup
        return self.client(
            tenant,
            lambda: GraylogClient(
                setup.url,
                setup.token,
                tenant=graylog.name,
                verify_ssl=tenant_tls_verify(setup.ssl, platform="graylog", tenant=graylog.name),
                timeout=timeout,
            ),
            key=f"{timeout:g}",
        )

    @staticmethod
    def _refused(tenant: SystemConfig.Tenant, exc: GraylogApiError) -> QueryRefused:
        return QueryRefused(f"Graylog refused the query on {tenant.name}", detail=exc.detail)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from opentide.core.errors import Errors

        client = self._client(tenant, request.timeout)
        body: dict[str, Any] = {
            "query": request.text,
            "streams": resolve_streams(request.index, tenant),
            "timerange": {
                "type": "absolute",
                "from": format_utc_z(request.window.start),
                "to": format_utc_z(request.window.end),
            },
            "size": request.limit + 1,
            "sort": "timestamp",
            "sort_order": "desc",
        }
        try:
            fields = requested_fields(request.text, client.version())
            if fields is not None:
                body["fields"] = fields
            payload = client.search_messages(body, timeout=request.timeout)
        except GraylogTenantError as exc:
            raise Errors.TenantConnectionError(str(exc)) from exc
        except GraylogApiError as exc:
            raise self._refused(tenant, exc) from exc
        columns, rows = _rows(payload)
        return QueryResult(
            columns=tuple(columns),
            rows=tuple(rows[: request.limit]),
            truncated=len(rows) > request.limit,
            language="lucene",
        )

    def check(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> LiveCheck:
        """``POST /api/search/validate`` over the request's window: the query is parsed, not run.

        ``ERROR`` explanations refuse the query; ``WARNING`` and ``INFO`` ones are
        the check's warnings, each with Graylog's line and column.
        """
        from opentide.core.errors import Errors

        client = self._client(tenant, request.timeout)
        body = {
            "query": request.text,
            "streams": resolve_streams(request.index, tenant),
            "timerange": {"type": "relative", "range": request.window.seconds},
        }
        try:
            verdict = client.validate_query(body, timeout=request.timeout)
        except GraylogTenantError as exc:
            raise Errors.TenantConnectionError(str(exc)) from exc
        except GraylogApiError as exc:
            raise self._refused(tenant, exc) from exc
        errors, warnings = read_verdict(verdict)
        if errors:
            raise QueryRefused(
                f"Graylog refused the query on {tenant.name}", detail="; ".join(errors)
            )
        return LiveCheck(warnings=tuple(f"{code}: {text}" for code, text in warnings))


def declare() -> GraylogQueryRunner:
    return GraylogQueryRunner()
