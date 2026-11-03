"""Run a process search (Lucene) on a Carbon Black Cloud tenant."""

from __future__ import annotations

from itertools import islice
from typing import TYPE_CHECKING, Any, ClassVar

from opentide.core.time import format_utc_z
from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.query.models import (
    LiveCheck,
    QueryRefused,
    QueryRequest,
    QueryResult,
    QueryTimedOut,
    columns_of,
    flatten,
)
from opentide.query.runner import QueryRunner

if TYPE_CHECKING:
    from cbc_sdk.rest_api import CBCloudAPI


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

        from opentide.core.errors import Errors
        from opentide.platforms.transport import read_timeout, transport_error

        api = self._api(tenant, timeout=request.timeout)
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
            if transport_error(exc) is not None and read_timeout(exc) is None:
                raise  # A connect timeout: reported once, as an unreachable tenant.
            raise QueryTimedOut(
                f"the process search did not finish within {request.timeout:g}s on {tenant.name}",
                timeout=request.timeout,
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

    def check(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> LiveCheck:
        """Carbon Black's ``search_validation`` call: the query is parsed, no search runs."""
        if not self._api(tenant, timeout=request.timeout).validate_process_query(request.text):
            raise QueryRefused(
                f"Carbon Black Cloud refused the query on {tenant.name}",
                detail="ensure each term has a value, and escape slashes, colons and spaces",
            )
        return LiveCheck()

    def _api(self, tenant: SystemConfig.Tenant, *, timeout: float) -> CBCloudAPI:
        """*tenant*'s SDK client whose every request may wait *timeout* seconds, made once."""
        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.platforms.carbon_black.client import CarbonBlackCloudService

        if not isinstance(tenant, ConfigurationModels.Systems.CarbonBlackCloud.Tenant):
            raise TypeError(
                f"expected a Carbon Black Cloud tenant, got {type(tenant).__qualname__}"
            )
        setup = tenant.setup
        reject_unsubstituted_placeholders(setup.url, setup.org_key, setup.token, client="CBC")
        cbc_tenant = tenant
        return self.client(
            tenant,
            lambda: CarbonBlackCloudService(cbc_tenant, timeout=timeout).service,
            key=f"{timeout:g}",
        )


def _document(process: Any) -> dict[str, Any]:
    info = getattr(process, "_info", None)
    return dict(info) if isinstance(info, dict) else {}


def declare() -> CarbonBlackQueryRunner:
    return CarbonBlackQueryRunner()
