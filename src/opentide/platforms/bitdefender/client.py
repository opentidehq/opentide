"""JSON-RPC 2.0 client for the GravityZone Incidents API (bitdefender-1.0, Deploy).

Every request is a ``POST`` to ``<url>/v1.0/jsonrpc/incidents`` with a fresh
string ``id``. A response with an ``error`` member is a failure whatever its
HTTP status. ``-32001``, HTTP 401 and HTTP 403 stop the tenant
(:class:`BitdefenderTenantError`); ``-32003`` and HTTP 429 are waited out
(``Retry-After``) and the same request is sent again, because a rate-limited
request was not executed. ``createCustomRule`` and ``deleteCustomRule`` are
paced at most five per rolling minute per API key, across every tenant of a
run that shares the key.

No transport-level retry is mounted: a create that got no answer must not be
sent again blindly. The deployer retries it once and reads a name conflict on
that retry as ``bitdefender_create_unconfirmed``.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from typing import Any

import requests

from opentide.platforms.transport import TenantSession

API_PATH = "/v1.0/jsonrpc/incidents"

#: JSON-RPC error codes GravityZone answers (RFC 0016, Public API).
UNAUTHORIZED = -32001
NOT_FOUND = -32002
TOO_MANY_REQUESTS = -32003
METHOD_NOT_FOUND = -32601

#: Methods paced per API key: at most :data:`PACED_CALLS` per :data:`PACE_WINDOW` seconds.
PACED_METHODS = frozenset({"createCustomRule", "deleteCustomRule"})
PACED_CALLS = 5
PACE_WINDOW = 60.0
#: Wait when a rate limit names no ``Retry-After``.
DEFAULT_RETRY_AFTER = 60.0
#: Rate-limited resends of one request before it fails.
MAX_RATE_LIMITED = 10

_NAME_CONFLICT = re.compile(
    r"already exists?|duplicate|name[^.]*(?:exists|taken|in use|unique)", re.IGNORECASE
)
_TYPE_MISMATCH = re.compile(
    r"\b(?:sub)?type\b[^.]*(?:mismatch|does not match|differ|cannot be changed)"
    r"|(?:mismatch|cannot change)[^.]*\b(?:sub)?type\b",
    re.IGNORECASE,
)


class BitdefenderTenantError(RuntimeError):
    """The tenant cannot take any rule: refused key, or no Incidents API."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class BitdefenderApiError(RuntimeError):
    """A JSON-RPC call failed for this rule only."""

    def __init__(
        self, method: str, code: int | None, message: str, details: str | None = None
    ) -> None:
        self.method = method
        self.code = code
        self.details = details
        text = f"{method}: error {code}: {message}" if code is not None else f"{method}: {message}"
        if details:
            text += f" ({details})"
        super().__init__(text)

    @property
    def text(self) -> str:
        return " ".join(part for part in (str(self.args[0]), self.details or "") if part)

    @property
    def name_conflict(self) -> bool:
        """GravityZone refused a create because the name exists in the company."""
        return self.method == "createCustomRule" and bool(_NAME_CONFLICT.search(self.text))

    @property
    def type_mismatch(self) -> bool:
        """GravityZone refused an update because the rule's kind differs."""
        return self.method == "updateCustomRule" and bool(_TYPE_MISMATCH.search(self.text))


class _Pacer:
    """At most :data:`PACED_CALLS` calls per rolling :data:`PACE_WINDOW` per API key."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[str, deque[float]] = {}

    def wait(self, key: str, clock: Callable[[], float], sleep: Callable[[float], None]) -> None:
        with self._lock:
            calls = self._calls.setdefault(key, deque())
            now = clock()
            while calls and now - calls[0] >= PACE_WINDOW:
                calls.popleft()
            if len(calls) >= PACED_CALLS:
                pause = PACE_WINDOW - (now - calls[0])
                if pause > 0:
                    sleep(pause)
                now = clock()
                while calls and now - calls[0] >= PACE_WINDOW:
                    calls.popleft()
            calls.append(now)

    def reset(self) -> None:
        with self._lock:
            self._calls.clear()


#: Shared by every client of the process, so tenants sharing a key share its budget.
PACER = _Pacer()


def _retry_after(response: requests.Response | None) -> float:
    value = response.headers.get("Retry-After") if response is not None else None
    try:
        return max(float(value), 0.0) if value is not None else DEFAULT_RETRY_AFTER
    except ValueError:
        return DEFAULT_RETRY_AFTER


def _details(error: dict[str, Any]) -> str | None:
    data = error.get("data")
    if isinstance(data, dict) and data.get("details") is not None:
        return str(data["details"])
    if isinstance(data, str):
        return data
    return None


class BitdefenderClient:
    """Custom rules on one GravityZone tenant, through the Incidents API."""

    def __init__(
        self,
        url: str,
        api_key: str,
        *,
        tenant: str,
        key_type: str = "personal",
        verify_ssl: bool = True,
        timeout: int = 30,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.endpoint = url.rstrip("/") + API_PATH
        self.tenant = tenant
        self.timeout = timeout
        self._sleep = sleep
        self._clock = clock
        # The pacer keys on a digest, so no key is held in a long-lived mapping.
        self._pace_key = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        self.session = TenantSession(verify=verify_ssl)
        self.session.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )
        if key_type == "service":
            self.session.headers["X-API-Key"] = api_key
        else:
            self.session.auth = (api_key, "")

    def call(self, method: str, params: dict[str, Any]) -> Any:
        """Send one JSON-RPC request and return its ``result``.

        Raises :class:`BitdefenderTenantError`, :class:`BitdefenderApiError`, or a
        :class:`requests.RequestException` when the call got no answer.
        """
        body = {"jsonrpc": "2.0", "method": method, "params": params, "id": uuid.uuid4().hex}
        for _attempt in range(MAX_RATE_LIMITED + 1):
            if method in PACED_METHODS:
                PACER.wait(self._pace_key, self._clock, self._sleep)
            response = self.session.post(self.endpoint, json=body, timeout=self.timeout)
            if response.status_code in (401, 403):
                raise BitdefenderTenantError(
                    "bitdefender_tenant_unauthorized",
                    f"tenant {self.tenant} refused the API key: HTTP {response.status_code}",
                )
            if response.status_code == 429:
                self._sleep(_retry_after(response))
                continue
            try:
                payload = response.json()
            except ValueError as exc:
                raise BitdefenderApiError(
                    method, None, f"HTTP {response.status_code}: the answer is not JSON"
                ) from exc
            error = payload.get("error") if isinstance(payload, dict) else None
            if isinstance(error, dict):
                code = error.get("code")
                message = str(error.get("message") or "")
                if code == TOO_MANY_REQUESTS:
                    self._sleep(_retry_after(response))
                    continue
                if code == UNAUTHORIZED:
                    raise BitdefenderTenantError(
                        "bitdefender_tenant_unauthorized",
                        f"tenant {self.tenant} refused the API key: {message}",
                    )
                if code == METHOD_NOT_FOUND:
                    raise BitdefenderTenantError(
                        "bitdefender_incidents_api_unavailable",
                        f"tenant {self.tenant} has no {method} (on-premises GravityZone has "
                        "no Incidents API)",
                    )
                raise BitdefenderApiError(
                    method, code if isinstance(code, int) else None, message, _details(error)
                )
            if response.status_code >= 300:
                raise BitdefenderApiError(method, None, f"HTTP {response.status_code}")
            if not isinstance(payload, dict) or "result" not in payload:
                raise BitdefenderApiError(method, None, "the answer has no result")
            return payload["result"]
        raise BitdefenderApiError(
            method, TOO_MANY_REQUESTS, f"still rate limited after {MAX_RATE_LIMITED} waits"
        )

    # --- custom rules ------------------------------------------------------------

    def create_rule(self, params: dict[str, Any]) -> Any:
        return self.call("createCustomRule", params)

    def update_rule(self, params: dict[str, Any]) -> Any:
        return self.call("updateCustomRule", params)

    def delete_rule(self, params: dict[str, Any]) -> Any:
        return self.call("deleteCustomRule", params)
