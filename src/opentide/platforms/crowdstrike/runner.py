"""Run a CrowdStrike Query Language (CQL) search on Falcon Next-Gen SIEM.

The search is a LogScale query job: started, polled until done, and stopped
when it outlives ``--timeout``. The OAuth client needs the ``NGSIEM: Read``
scope; deploy's correlation-rule scope alone is not enough.
"""

from __future__ import annotations

import contextlib
import re
import time
from collections.abc import Callable
from typing import Any, ClassVar
from urllib.parse import quote

import requests

from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.platforms.transport import TenantSession
from opentide.query.models import QueryRefused, QueryRequest, QueryResult, columns_of, flatten
from opentide.query.runner import QueryRunner

#: The repository searched when ``--index`` names none: every event Falcon holds.
DEFAULT_REPOSITORY = "search-all"

#: Replaced in tests, so polling costs no wall-clock time.
sleep: Callable[[float], None] = time.sleep

_HEAD = re.compile(r"\|\s*(?:head|tail)\s*\(", re.IGNORECASE)


class CrowdstrikeQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("cql",)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.platforms.crowdstrike.client import CrowdstrikeService

        if not isinstance(tenant, ConfigurationModels.Systems.Crowdstrike.Tenant):
            raise TypeError(f"expected a CrowdStrike tenant, got {type(tenant).__qualname__}")
        setup = tenant.setup
        reject_unsubstituted_placeholders(
            setup.client_id, setup.client_secret, client="CrowdStrike"
        )
        service = CrowdstrikeService(tenant)
        repository = request.index[0] if request.index else DEFAULT_REPOSITORY
        jobs = (
            f"{service._get_base_api(setup.api)}/humio/api/v1/repositories/"
            f"{quote(repository, safe='')}/queryjobs"
        )
        sent = cql_with_limit(request.text, request.limit)
        started = service.session.post(
            jobs,
            json={
                "queryString": sent,
                "start": _epoch_ms(request.window.start.timestamp()),
                "end": _epoch_ms(request.window.end.timestamp()),
                "isLive": False,
            },
        )
        job = _json(started, tenant.name, "start the search")
        job_id = str(job.get("id") or "")
        if not job_id:
            raise QueryRefused(f"Next-Gen SIEM returned no search id on {tenant.name}")
        status_url = f"{jobs}/{quote(job_id, safe='')}"
        deadline = time.monotonic() + request.timeout
        delay = 0.5
        try:
            while True:
                status = _json(service.session.get(status_url), tenant.name, "read the search")
                if status.get("cancelled"):
                    raise QueryRefused(f"the search was cancelled on {tenant.name}")
                if status.get("done"):
                    break
                if time.monotonic() >= deadline:
                    raise QueryRefused(
                        f"the search did not finish within {request.timeout:g}s on {tenant.name}",
                        detail="narrow the window or raise --timeout",
                    )
                sleep(delay)
                delay = min(delay * 2, 5.0)
        except BaseException:
            _stop(service.session, status_url)
            raise
        rows = [
            flatten(event) for event in status.get("events", []) or [] if isinstance(event, dict)
        ]
        warnings = tuple(
            str(item.get("message", item)) if isinstance(item, dict) else str(item)
            for item in status.get("messages", []) or []
        )
        return QueryResult(
            columns=columns_of(rows[: request.limit]),
            rows=tuple(rows[: request.limit]),
            truncated=len(rows) > request.limit,
            warnings=warnings,
            vendor_query_id=job_id,
            sent=sent if sent != request.text.strip() else None,
            language="cql",
        )


def cql_with_limit(query: str, limit: int) -> str:
    """*query* with ``| head(limit=limit+1)`` appended, unless it has a ``head``/``tail``."""
    text = query.strip()
    if _HEAD.search(text):
        return text
    return f"{text}\n| head(limit={limit + 1})"


def _epoch_ms(seconds: float) -> int:
    return int(seconds * 1000)


def _json(response: requests.Response, tenant: str, action: str) -> dict[str, Any]:
    if response.status_code >= 400:
        if response.status_code == 403:
            detail = "the API client needs the NGSIEM: Read scope"
        else:
            detail = response.text[:500] or None
        raise QueryRefused(
            f"Next-Gen SIEM could not {action} on {tenant} (HTTP {response.status_code})",
            detail=detail,
        )
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _stop(session: TenantSession, url: str) -> None:
    """Stop a search we no longer wait for; a failure to stop it is not the caller's error."""
    with contextlib.suppress(requests.RequestException):
        session.delete(url)


def declare() -> CrowdstrikeQueryRunner:
    return CrowdstrikeQueryRunner()
