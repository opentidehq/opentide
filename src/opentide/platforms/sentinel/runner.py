"""Run a KQL query on a Sentinel (Log Analytics) workspace."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.platforms.transport import tenant_tls_verify
from opentide.query.models import QueryColumn, QueryRefused, QueryRequest, QueryResult
from opentide.query.runner import QueryRunner, kql_with_limit

if TYPE_CHECKING:
    from azure.monitor.query import LogsTable


class SentinelQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("kql",)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
        from azure.identity import ClientSecretCredential
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus

        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.core.errors import Errors

        if not isinstance(tenant, ConfigurationModels.Systems.Sentinel.Tenant):
            raise TypeError(f"expected a Sentinel tenant, got {type(tenant).__qualname__}")
        setup = tenant.setup
        reject_unsubstituted_placeholders(
            setup.azure_tenant_id, setup.azure_client_id, setup.azure_client_secret, client="Azure"
        )

        def _client() -> LogsQueryClient:
            verify = tenant_tls_verify(setup.ssl, platform="sentinel", tenant=tenant.name)
            credential = ClientSecretCredential(
                setup.azure_tenant_id,
                setup.azure_client_id,
                setup.azure_client_secret,
                connection_verify=verify,
            )
            return LogsQueryClient(credential=credential, connection_verify=verify)

        client = self.client(tenant, _client)
        sent = kql_with_limit(request.text, request.limit)
        try:
            response = client.query_workspace(
                workspace_id=setup.workspace_id,
                query=sent,
                timespan=(request.window.start, request.window.end),
                server_timeout=int(min(request.timeout, 600)),
            )
        except ClientAuthenticationError as exc:
            raise Errors.TenantConnectionError(str(exc.message)) from exc
        except HttpResponseError as exc:
            raise QueryRefused(
                f"Log Analytics refused the query on {tenant.name}", detail=_inner_message(exc)
            ) from exc
        warnings: list[str] = []
        partial = response.status == LogsQueryStatus.PARTIAL
        if partial:
            tables = list(getattr(response, "partial_data", []) or [])
            error = getattr(response, "partial_error", None)
            warnings.append(f"partial result: {getattr(error, 'message', error)}")
        else:
            tables = list(getattr(response, "tables", []) or [])
        if len(tables) > 1:
            warnings.append(f"the query returned {len(tables)} tables; showing the first")
        columns, rows = _table(tables[0]) if tables else ((), [])
        return QueryResult(
            columns=columns,
            rows=tuple(rows[: request.limit]),
            truncated=len(rows) > request.limit,
            partial=partial,
            warnings=tuple(warnings),
            sent=sent if sent != request.text.strip() else None,
            language="kql",
        )


def _table(table: LogsTable) -> tuple[tuple[QueryColumn, ...], list[dict[str, Any]]]:
    names = [str(name) for name in table.columns]
    types = list(getattr(table, "columns_types", None) or [None] * len(names))
    columns = tuple(
        QueryColumn(name, None if kind is None else str(kind))
        for name, kind in zip(names, types, strict=False)
    )
    rows = [dict(zip(names, list(row), strict=False)) for row in table.rows]
    return columns, rows


def _inner_message(error: Any) -> str:
    """The KQL parser's message inside an Azure Monitor error, else the error text."""
    odata = getattr(error, "error", None)
    inner = getattr(odata, "innererror", None)
    if isinstance(inner, dict):
        nested = inner.get("innererror")
        if isinstance(nested, dict) and nested.get("message"):
            return str(nested["message"])
        if inner.get("message"):
            return str(inner["message"])
    return str(getattr(error, "message", None) or error)


def declare() -> SentinelQueryRunner:
    return SentinelQueryRunner()
