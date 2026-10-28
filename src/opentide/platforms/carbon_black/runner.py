"""Run a process search (Lucene) on a Carbon Black Cloud tenant."""

from __future__ import annotations

from itertools import islice
from typing import Any, ClassVar

from opentide.core.time import format_utc_z
from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.query.models import QueryRefused, QueryRequest, QueryResult, columns_of, flatten
from opentide.query.runner import QueryRunner


class CarbonBlackQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("lucene",)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from cbc_sdk.errors import (
            ApiError,
            QuerySyntaxError,
            TimeoutError,
            UnauthorizedError,
        )
        from cbc_sdk.errors import (
            ConnectionError as CbcConnectionError,
        )
        from cbc_sdk.platform import Process

        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.core.errors import Errors
        from opentide.platforms.carbon_black.client import CarbonBlackCloudService

        if not isinstance(tenant, ConfigurationModels.Systems.CarbonBlackCloud.Tenant):
            raise TypeError(
                f"expected a Carbon Black Cloud tenant, got {type(tenant).__qualname__}"
            )
        setup = tenant.setup
        reject_unsubstituted_placeholders(setup.url, setup.org_key, setup.token, client="CBC")
        api = CarbonBlackCloudService(tenant).service
        query = (
            api.select(Process)
            .where(request.text)
            .set_time_range(
                start=format_utc_z(request.window.start), end=format_utc_z(request.window.end)
            )
            .set_rows(request.limit + 1)
        )
        query.timeout(int(request.timeout * 1000))
        try:
            found = list(islice(query, request.limit + 1))
        except UnauthorizedError as exc:
            raise Errors.TenantConnectionError(str(exc)) from exc
        except QuerySyntaxError as exc:
            raise QueryRefused(
                f"Carbon Black Cloud refused the query on {tenant.name}", detail=str(exc)
            ) from exc
        except TimeoutError as exc:
            raise QueryRefused(
                f"the process search did not finish within {request.timeout:g}s on {tenant.name}",
                detail="narrow the window or raise --timeout",
            ) from exc
        except CbcConnectionError:
            raise  # Reported once, as an unreachable tenant.
        except ApiError as exc:
            raise QueryRefused(
                f"Carbon Black Cloud refused the query on {tenant.name}", detail=str(exc)
            ) from exc
        rows = [flatten(_document(item)) for item in found]
        return QueryResult(
            columns=columns_of(rows[: request.limit]),
            rows=tuple(rows[: request.limit]),
            truncated=len(rows) > request.limit,
            language="lucene",
        )


def _document(process: Any) -> dict[str, Any]:
    info = getattr(process, "_info", None)
    return dict(info) if isinstance(info, dict) else {}


def declare() -> CarbonBlackQueryRunner:
    return CarbonBlackQueryRunner()
