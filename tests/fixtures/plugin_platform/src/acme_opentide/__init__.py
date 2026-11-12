"""The Acme detection platform for opentide: a sample platform plugin.

Acme's API, as this sample knows it (every call takes ``Authorization:
Bearer <token>`` and answers JSON):

- ``PUT /api/rules/<rule id>`` with ``{"name", "query", "severity"}``
  creates or replaces a rule and answers ``{"id": <Acme's id>}``;
- ``POST /api/validate`` with ``{"query"}`` answers ``{"valid": bool,
  "error": str | None}``;
- ``POST /api/search`` with ``{"query", "from", "to", "limit"}`` answers
  ``{"rows": [...], "more": bool}``.

The tenant's ``setup`` names ``url`` and ``token``.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from opentide.plugins import (
    DeployRequest,
    DeployResult,
    LiveCheck,
    PlatformAuthenticationError,
    PlatformPlugin,
    PlatformRefused,
    QueryRequest,
    QueryResult,
    Tenant,
)


class AcmeConfig(BaseModel):
    """A rule's ``configurations.acme`` block."""

    model_config = ConfigDict(extra="forbid")

    status: str | None = None
    query: str
    language: Literal["acmeql"] = "acmeql"
    severity: int = Field(ge=1, le=5)


class AcmePlatform(PlatformPlugin):
    """Deploys, checks and runs Acme queries."""

    configuration_model = AcmeConfig

    def _call(self, tenant: Tenant, path: str, payload: dict[str, Any], method: str) -> Any:
        url = tenant.setup.get("url")
        token = tenant.setup.get("token")
        if not url or not token:
            raise PlatformAuthenticationError(f"tenant {tenant.name} needs url and token")
        request = urllib.request.Request(
            f"{url.rstrip('/')}{path}",
            data=json.dumps(payload).encode("utf-8"),
            method=method,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        context = ssl.create_default_context()
        if not tenant.verify_tls:
            # The tenant's own `ssl = false`.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(request, timeout=tenant.timeout, context=context) as answer:
                return json.loads(answer.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            if error.code in (401, 403):
                raise PlatformAuthenticationError("Acme refused the token", detail) from error
            raise PlatformRefused(f"Acme answered {error.code}", detail) from error

    def deploy(self, tenant: Tenant, request: DeployRequest) -> DeployResult:
        block = request.body["configuration"]
        answer = self._call(
            tenant,
            f"/api/rules/{request.rule_id}",
            {
                "name": request.body["rule"]["name"],
                "query": block["query"],
                "severity": block["severity"],
            },
            "PUT",
        )
        return DeployResult(remote_id=str(answer["id"]), operation=request.operation)

    def validate_query(self, tenant: Tenant, request: QueryRequest) -> LiveCheck:
        answer = self._call(tenant, "/api/validate", {"query": request.text}, "POST")
        if answer.get("valid"):
            return LiveCheck()
        return LiveCheck(errors=[answer.get("error") or "Acme refused the query"])

    def run_query(self, tenant: Tenant, request: QueryRequest) -> QueryResult:
        answer = self._call(
            tenant,
            "/api/search",
            {
                "query": request.text,
                "from": request.start,
                "to": request.end,
                "limit": request.limit,
            },
            "POST",
        )
        rows = answer.get("rows", [])
        return QueryResult(
            rows=rows[: request.limit],
            truncated=bool(answer.get("more")) or len(rows) > request.limit,
            language="acmeql",
        )
