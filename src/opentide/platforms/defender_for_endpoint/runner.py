"""Run an advanced hunting (KQL) query on a Defender XDR tenant through Microsoft Graph."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, ClassVar

from opentide.core.time import format_utc_z, utc_now
from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.query.models import QueryColumn, QueryRefused, QueryRequest, QueryResult
from opentide.query.runner import QueryRunner, kql_with_limit

#: Advanced hunting keeps 30 days of data; Graph refuses a longer timespan.
MAX_LOOKBACK_DAYS = 30


class DefenderQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("kql",)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.platforms.defender_for_endpoint.client import (
            DefenderForEndpointService,
            _error_message,
        )

        if not isinstance(tenant, ConfigurationModels.Systems.DefenderForEndpoint.Tenant):
            raise TypeError(f"expected a Defender tenant, got {type(tenant).__qualname__}")
        oldest = utc_now() - timedelta(days=MAX_LOOKBACK_DAYS)
        if request.window.start < oldest:
            raise QueryRefused(
                f"advanced hunting keeps {MAX_LOOKBACK_DAYS} days of data: start the window "
                f"after {format_utc_z(oldest)}"
            )
        setup = tenant.setup
        reject_unsubstituted_placeholders(
            setup.tenant_id, setup.client_id, setup.client_secret, client="Microsoft Graph"
        )
        service = self.client(tenant, lambda: DefenderForEndpointService(tenant))
        sent = kql_with_limit(request.text, request.limit)
        timespan = f"{format_utc_z(request.window.start)}/{format_utc_z(request.window.end)}"
        response = service.session.post(
            url=service.HUNTING_QUERY_ENDPOINT,
            json={"Query": sent, "Timespan": timespan},
            timeout=request.timeout,
        )
        if response.status_code != 200:
            message = (
                f"Graph refused the hunting query on {tenant.name} (HTTP {response.status_code})"
            )
            if response.status_code == 403:
                message += ": the app registration needs ThreatHunting.Read.All"
            raise QueryRefused(message, detail=str(_error_message(response)))
        body: dict[str, Any] = response.json()
        schema = body.get("schema", body.get("Schema", [])) or []
        columns = tuple(
            QueryColumn(
                str(column.get("name") or column.get("Name")),
                column.get("type") or column.get("Type"),
            )
            for column in schema
            if isinstance(column, dict)
        )
        rows = [row for row in body.get("results", body.get("Results", [])) or [] if row]
        return QueryResult(
            columns=columns,
            rows=tuple(rows[: request.limit]),
            truncated=len(rows) > request.limit,
            sent=sent if sent != request.text.strip() else None,
            language="kql",
        )


def declare() -> DefenderQueryRunner:
    return DefenderQueryRunner()
