"""HTTPS client for the Exabeam New-Scale APIs (exabeam-1.0, Deploy and Query validation).

One client serves one tenant for a run. It asks for one bearer token
(``POST /auth/v1/token``, client credentials) and reuses it; a ``401`` whose
body says the token expired gets one new token and one retry. A ``401``
after that, or a ``403``, stops the tenant (``exabeam_tenant_unauthorized``),
as a ``409`` ("Feature is not enabled for subscription") does
(``exabeam_feature_unavailable``).

Exabeam allows 100 requests per minute per source IP, so every request of
every Exabeam client in the process goes through one pacer: at most 100 per
rolling minute. A ``429`` waits out ``Retry-After`` (60 seconds when absent)
and sends the same request again, because a rate-limited request was not
executed.

No transport-level retry is mounted: a create that got no answer must not
be sent again (``exabeam_create_unconfirmed``).
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from typing import Any

import requests

from opentide.core.environment import reject_unsubstituted_placeholders
from opentide.platforms.exabeam.compile import RULES_PATH, SEARCH_PATH
from opentide.platforms.transport import TenantSession, not_json_detail

TOKEN_PATH = "/auth/v1/token"

#: Exabeam's limit: requests per :data:`PACE_WINDOW` seconds per source IP.
PACED_CALLS = 100
PACE_WINDOW = 60.0
#: Wait when a ``429`` names no ``Retry-After``.
DEFAULT_RETRY_AFTER = 60.0
#: Rate-limited resends of one request before it fails.
MAX_RATE_LIMITED = 10

UNAUTHORIZED = "exabeam_tenant_unauthorized"
FEATURE_UNAVAILABLE = "exabeam_feature_unavailable"

#: A ``401`` body that says the token expired ("Jwt is expired").
_EXPIRED = re.compile(r"expired", re.IGNORECASE)


class ExabeamTenantError(RuntimeError):
    """The tenant cannot take any request: refused credentials, or no licence for the feature."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class ExabeamApiError(RuntimeError):
    """A request failed for this rule or query only.

    ``status`` is the HTTP status; ``errors`` are Exabeam's ``errors[]``
    entries and ``trace_id`` its ``traceId``, when the answer carried them.
    """

    def __init__(
        self,
        action: str,
        status: int,
        message: str,
        *,
        errors: tuple[dict[str, Any], ...] = (),
        trace_id: str | None = None,
    ) -> None:
        self.action = action
        self.status = status
        self.errors = errors
        self.trace_id = trace_id
        self.detail = message
        super().__init__(f"{action}: HTTP {status}: {message}")

    @property
    def not_found(self) -> bool:
        return self.status == 404


def _error_entry(entry: Mapping[str, Any]) -> str:
    """One ``errors[]`` entry as ``code: message (fields: a, b)``."""
    code = entry.get("code")
    message = str(entry.get("message") or "").strip()
    text = f"{code}: {message}" if code and message else str(code or message)
    fields = entry.get("fields")
    if isinstance(fields, list) and fields:
        text += f" (fields: {', '.join(str(field) for field in fields)})"
    elif isinstance(fields, (str, Mapping)) and fields:
        text += f" (fields: {fields})"
    return text


def api_error(action: str, response: requests.Response) -> ExabeamApiError:
    """The :class:`ExabeamApiError` a non-2xx *response* reports, with Exabeam's details."""
    try:
        payload = response.json()
    except ValueError:
        payload = None
    errors: tuple[dict[str, Any], ...] = ()
    trace_id: str | None = None
    message = ""
    if isinstance(payload, Mapping):
        raw = payload.get("errors")
        if isinstance(raw, list):
            errors = tuple(entry for entry in raw if isinstance(entry, dict))
        trace = payload.get("traceId")
        trace_id = str(trace) if trace else None
        message = "; ".join(_error_entry(entry) for entry in errors)
        if not message:
            message = str(payload.get("message") or payload.get("error") or "")
    if not message:
        message = not_json_detail(response) or response.text[:500] or response.reason or ""
    if trace_id:
        message = f"{message} (traceId {trace_id})" if message else f"traceId {trace_id}"
    return ExabeamApiError(action, response.status_code, message, errors=errors, trace_id=trace_id)


class _Pacer:
    """At most :data:`PACED_CALLS` requests per rolling :data:`PACE_WINDOW`, process-wide."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: deque[float] = deque()

    def wait(self, clock: Callable[[], float], sleep: Callable[[float], None]) -> None:
        with self._lock:
            now = clock()
            while self._calls and now - self._calls[0] >= PACE_WINDOW:
                self._calls.popleft()
            if len(self._calls) >= PACED_CALLS:
                pause = PACE_WINDOW - (now - self._calls[0])
                if pause > 0:
                    sleep(pause)
                now = clock()
                while self._calls and now - self._calls[0] >= PACE_WINDOW:
                    self._calls.popleft()
            self._calls.append(now)

    def reset(self) -> None:
        with self._lock:
            self._calls.clear()


#: Shared by every Exabeam client of the process: the limit is per source IP, so
#: every tenant of a run shares it.
PACER = _Pacer()


def _retry_after(response: requests.Response) -> float:
    value = response.headers.get("Retry-After")
    try:
        return max(float(value), 0.0) if value is not None else DEFAULT_RETRY_AFTER
    except ValueError:
        return DEFAULT_RETRY_AFTER


def _token_expired(response: requests.Response) -> bool:
    """Whether a ``401`` says the bearer token expired, in its body or its challenge."""
    challenge = response.headers.get("WWW-Authenticate", "")
    return bool(_EXPIRED.search(response.text or "") or _EXPIRED.search(challenge))


class ExabeamClient:
    """Correlation rules and Search on one Exabeam tenant."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        *,
        tenant: str,
        verify_ssl: bool = True,
        timeout: float = 30,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        # An unset $EXABEAM_CLIENT_ID stays the literal placeholder: refuse it
        # rather than send it as a credential.
        reject_unsubstituted_placeholders(client_id, client_secret, client="Exabeam")
        self.base_url = base_url.rstrip("/")
        self.tenant = tenant
        self.timeout = timeout
        self._client_id = client_id
        self._client_secret = client_secret
        self._sleep = sleep
        self._clock = clock
        self._token: str | None = None
        self.session = TenantSession(verify=verify_ssl)
        self.session.headers.update({"Accept": "application/json"})

    # --- transport ------------------------------------------------------------------

    def _send(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> requests.Response:
        """One request, paced, with 429s waited out. No status is judged here."""
        for _attempt in range(MAX_RATE_LIMITED + 1):
            PACER.wait(self._clock, self._sleep)
            response = self.session.request(
                method,
                self.base_url + path,
                json=json,
                params=params,
                headers=dict(headers or {}),
                timeout=timeout or self.timeout,
            )
            if response.status_code != 429:
                return response
            self._sleep(_retry_after(response))
        raise ExabeamApiError(
            f"{method} {path}", 429, f"still rate limited after {MAX_RATE_LIMITED} waits"
        )

    def _refused(self, response: requests.Response, what: str) -> ExabeamTenantError:
        detail = not_json_detail(response) or (response.text or "")[:300]
        return ExabeamTenantError(
            UNAUTHORIZED,
            f"tenant {self.tenant} refused {what}: HTTP {response.status_code}"
            + (f" ({detail.strip()})" if detail and detail.strip() else ""),
        )

    def token(self, *, refresh: bool = False) -> str:
        """The bearer token: requested once per client, again only when *refresh*."""
        if self._token is not None and not refresh:
            return self._token
        response = self._send(
            "POST",
            TOKEN_PATH,
            json={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "client_credentials",
            },
        )
        if response.status_code in (400, 401, 403):
            raise self._refused(response, "the API key")
        if response.status_code >= 300:
            raise api_error("POST /auth/v1/token", response)
        try:
            payload = response.json()
        except ValueError as exc:
            raise ExabeamApiError(
                "POST /auth/v1/token", response.status_code, "the answer is not JSON"
            ) from exc
        token = payload.get("access_token") if isinstance(payload, Mapping) else None
        if not isinstance(token, str) or not token:
            raise ExabeamApiError(
                "POST /auth/v1/token", response.status_code, "the answer has no access_token"
            )
        self._token = token
        return token

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> requests.Response:
        """An authenticated request. Raises :class:`ExabeamTenantError` for 401/403/409.

        Every other answer is returned for the caller to judge; a request that
        got no answer raises :class:`requests.RequestException`.
        """
        refreshed = False
        while True:
            headers = {"Authorization": f"Bearer {self.token()}"}
            response = self._send(
                method, path, json=json, params=params, headers=headers, timeout=timeout
            )
            if response.status_code == 401 and not refreshed and _token_expired(response):
                refreshed = True
                self.token(refresh=True)
                continue
            if response.status_code in (401, 403):
                raise self._refused(response, f"{method} {path}")
            if response.status_code == 409:
                detail = api_error(f"{method} {path}", response).detail
                raise ExabeamTenantError(
                    FEATURE_UNAVAILABLE,
                    f"tenant {self.tenant} answered {method} {path} with HTTP 409: "
                    + (detail or "the feature is not enabled for the subscription"),
                )
            return response

    # --- correlation rules --------------------------------------------------------------

    def rules_named(self, name: str) -> list[dict[str, Any]]:
        """``GET /correlation-rules/v2/rules?nameContains=<name>``: rules whose name holds *name*.

        The API answers one array, with no paging.
        """
        action = f"GET {RULES_PATH}?nameContains"
        response = self.request("GET", RULES_PATH, params={"nameContains": name})
        if response.status_code >= 300:
            raise api_error(action, response)
        payload = _json(response, action)
        if isinstance(payload, Mapping):
            payload = payload.get("rules", payload.get("items", []))
        if not isinstance(payload, list):
            raise ExabeamApiError(action, response.status_code, "the answer is not a list of rules")
        return [rule for rule in payload if isinstance(rule, dict)]

    def create_rule(self, body: dict[str, Any]) -> dict[str, Any]:
        """``POST /correlation-rules/v2/rules``: the rule Exabeam created."""
        return self._rule_call("POST", RULES_PATH, body)

    def update_rule(self, rule_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """``PUT /correlation-rules/v2/rules/{id}``: the rule as Exabeam stored it."""
        return self._rule_call("PUT", f"{RULES_PATH}/{rule_id}", body)

    def delete_rule(self, rule_id: str) -> None:
        """``DELETE /correlation-rules/v2/rules/{id}``. Raises with ``not_found`` on a 404."""
        path = f"{RULES_PATH}/{rule_id}"
        response = self.request("DELETE", path)
        if response.status_code >= 300:
            raise api_error(f"DELETE {path}", response)

    def _rule_call(self, method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        action = f"{method} {path}"
        response = self.request(method, path, json=body)
        if response.status_code >= 300:
            raise api_error(action, response)
        payload = _json(response, action)
        return payload if isinstance(payload, dict) else {}

    # --- search -------------------------------------------------------------------------

    def search(self, body: dict[str, Any], *, timeout: float | None = None) -> requests.Response:
        """``POST /search/v2/events``. The answer is returned whatever its status."""
        return self.request("POST", SEARCH_PATH, json=body, timeout=timeout)


def _json(response: requests.Response, action: str) -> Any:
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError as exc:
        raise ExabeamApiError(
            action,
            response.status_code,
            not_json_detail(response) or "the answer is not JSON",
        ) from exc
