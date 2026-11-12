"""Chronicle API v1 client for one Google SecOps instance (google-secops-1.0).

Every request goes to ``<endpoint>/v1/projects/<project>/locations/<location>/
instances/<instance>`` with an OAuth 2.0 access token for the
``cloud-platform`` scope: from the service-account key the tenant's
``credentials`` variable holds (a JSON document or the path to one), or from
Application Default Credentials. Requests run on a
:class:`~opentide.platforms.transport.TenantSession`, so TLS follows the
tenant's ``ssl`` and nothing waits forever.

HTTP 401 and 403 stop the tenant (:class:`GoogleSecopsTenantError`). HTTP 429
and 503 are waited out, ``Retry-After`` when Google sends one, else 2, 4 and
8 seconds, and the same request is sent again; then the call fails. Any other
error is a :class:`GoogleSecopsApiError` with Google's ``error.status`` and
``error.message``. No transport-level retry is mounted: a create that got no
answer is not sent again (``google_secops_create_unconfirmed``).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import requests

from opentide.platforms.transport import TenantSession, not_json_detail

#: The OAuth 2.0 scope every request's token carries.
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
#: Seconds each request may take.
DEFAULT_TIMEOUT = 60.0
#: Waits after a 429 or 503 that names no ``Retry-After``. A request is resent at
#: most this many times, whether or not Google names the wait; then the call fails.
BACKOFF = (2.0, 4.0, 8.0)
#: The most one ``Retry-After`` is honoured for, in seconds.
MAX_RETRY_AFTER = 300.0
RETRY_STATUSES = frozenset({429, 503})


class Credentials(Protocol):
    """What the client needs of a ``google.auth`` credentials object."""

    token: str | None

    @property
    def valid(self) -> bool: ...

    def refresh(self, request: Any) -> None: ...


class GoogleSecopsTenantError(RuntimeError):
    """The instance cannot take any request: refused or missing credentials."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class GoogleSecopsApiError(RuntimeError):
    """One request failed: Google's HTTP status, ``error.status`` and ``error.message``."""

    def __init__(self, method: str, path: str, http_status: int, status: str, message: str) -> None:
        self.method = method
        self.path = path
        self.http_status = http_status
        self.status = status
        self.message = message
        super().__init__(f"{method} {path}: HTTP {http_status} {status}: {message}".rstrip(": "))

    @property
    def not_found(self) -> bool:
        return self.http_status == 404 or self.status == "NOT_FOUND"

    @property
    def conflict(self) -> bool:
        """A stale ``etag`` (``ABORTED``) or another concurrent change."""
        return self.http_status == 409 or self.status == "ABORTED"

    @property
    def failed_precondition(self) -> bool:
        return self.status == "FAILED_PRECONDITION"


def load_credentials(value: str | None) -> Credentials:
    """The credentials for a tenant's resolved ``credentials`` *value*.

    A service-account key as a JSON document or the path to one; ``None`` uses
    Application Default Credentials. Only a service-account key is read from
    the variable: another credential type (an external account runs commands
    to fetch its token) is refused. A value still ``$NAME`` is an unset
    variable: refused, rather than read as a path.
    """
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError
    from google.oauth2 import service_account

    if value is None:
        try:
            credentials, _project = google.auth.default(scopes=[SCOPE])
        except DefaultCredentialsError as exc:
            raise GoogleSecopsTenantError(
                "google_secops_credentials_missing",
                f"no credentials: the tenant names none and Application Default Credentials "
                f"are not set up ({exc})",
            ) from exc
        return credentials
    if value.startswith("$"):
        raise GoogleSecopsTenantError(
            "google_secops_credentials_missing",
            f"the credentials variable {value[1:]} is not set: set it to a service-account key "
            "(JSON) or the path to one",
        )
    text = value
    if not value.lstrip().startswith("{"):
        path = Path(value).expanduser()
        if not path.is_file():
            raise GoogleSecopsTenantError(
                "google_secops_credentials_missing",
                "the credentials variable names no file and holds no JSON key",
            )
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            raise GoogleSecopsTenantError(
                "google_secops_credentials_missing", f"cannot read the credentials file: {exc}"
            ) from exc
    try:
        info = json.loads(text)
        if not isinstance(info, dict) or info.get("type") != "service_account":
            raise ValueError("the key is not a service-account key (type: service_account)")
        return service_account.Credentials.from_service_account_info(info, scopes=[SCOPE])
    except ValueError as exc:
        # json.JSONDecodeError is a ValueError, and so is a malformed key.
        raise GoogleSecopsTenantError(
            "google_secops_credentials_missing", f"cannot load Google credentials: {exc}"
        ) from exc


def _retry_after(response: requests.Response) -> float | None:
    value = response.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return min(max(float(value), 0.0), MAX_RETRY_AFTER)
    except ValueError:
        return None


def _error_of(response: requests.Response) -> tuple[str, str]:
    """Google's ``error.status`` and ``error.message``, or a description of the answer."""
    try:
        payload = response.json()
    except ValueError:
        return "", not_json_detail(response) or f"HTTP {response.status_code}"
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("status") or ""), str(error.get("message") or "")
    return "", f"HTTP {response.status_code}"


class GoogleSecopsClient:
    """Rules, deployments, verification and search on one Google SecOps instance."""

    def __init__(
        self,
        *,
        endpoint: str,
        instance: str,
        credentials: Credentials,
        tenant: str,
        verify_ssl: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
        sleep: Callable[[float], None] = time.sleep,
        session: TenantSession | None = None,
    ) -> None:
        self.base = f"{endpoint.rstrip('/')}/v1/{instance}"
        self.instance = instance
        self.tenant = tenant
        self.timeout = timeout
        self._sleep = sleep
        self._credentials = credentials
        self.session = session if session is not None else TenantSession(verify=verify_ssl)
        self.session.headers.update({"Accept": "application/json"})

    @classmethod
    def for_tenant(
        cls, tenant: Any, *, timeout: float = DEFAULT_TIMEOUT, **kwargs: Any
    ) -> GoogleSecopsClient:
        """The client for a loaded ``google_secops`` tenant."""
        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.platforms.google_secops.compile import default_endpoint, instance_resource
        from opentide.platforms.transport import tenant_tls_verify

        setup = tenant.setup
        reject_unsubstituted_placeholders(
            setup.project, setup.location, setup.instance, client="Google SecOps"
        )
        endpoint = setup.endpoint or default_endpoint(setup.location)
        reject_unsubstituted_placeholders(endpoint, client="Google SecOps")
        return cls(
            endpoint=endpoint,
            instance=instance_resource(setup.project, setup.location, setup.instance),
            credentials=load_credentials(setup.credentials),
            tenant=tenant.name,
            verify_ssl=tenant_tls_verify(setup.ssl, platform="google_secops", tenant=tenant.name),
            timeout=timeout,
            **kwargs,
        )

    # --- transport -----------------------------------------------------------------

    def _token(self) -> str:
        if not self._credentials.valid:
            from google.auth.exceptions import RefreshError, TransportError
            from google.auth.transport.requests import Request

            try:
                self._credentials.refresh(Request(session=self.session))
            except RefreshError as exc:
                raise GoogleSecopsTenantError(
                    "google_secops_tenant_unauthorized",
                    f"tenant {self.tenant}: Google refused the credentials ({exc})",
                ) from exc
            except TransportError as exc:
                raise requests.ConnectionError(
                    f"cannot reach Google's token endpoint: {exc}"
                ) from exc
        token = self._credentials.token
        if not token:
            raise GoogleSecopsTenantError(
                "google_secops_tenant_unauthorized",
                f"tenant {self.tenant}: the credentials gave no access token",
            )
        return token

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send one request and return its JSON answer.

        *path* is relative to the instance resource: ``"rules"``,
        ``":verifyRuleText"``. Raises :class:`GoogleSecopsTenantError`,
        :class:`GoogleSecopsApiError`, or a :class:`requests.RequestException`
        when the request got no answer.
        """
        url = self.base + path if path.startswith(":") else f"{self.base}/{path}"
        retries = 0
        while True:
            headers = {"Authorization": f"Bearer {self._token()}"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            response = self.session.request(
                method,
                url,
                params=dict(params) if params else None,
                json=dict(body) if body is not None else None,
                headers=headers,
                timeout=self.timeout,
            )
            if response.status_code in RETRY_STATUSES and retries < len(BACKOFF):
                # Retry-After counts against the same budget: a tenant that keeps
                # naming a wait must not hold the run forever.
                wait = _retry_after(response)
                self._sleep(BACKOFF[retries] if wait is None else wait)
                retries += 1
                continue
            if response.status_code in (401, 403):
                status, message = _error_of(response)
                raise GoogleSecopsTenantError(
                    "google_secops_tenant_unauthorized",
                    f"tenant {self.tenant} refused the request (HTTP {response.status_code}"
                    f"{' ' + status if status else ''}): {message}",
                )
            if response.status_code >= 300:
                status, message = _error_of(response)
                raise GoogleSecopsApiError(method, path, response.status_code, status, message)
            if not response.content:
                return {}
            try:
                payload = response.json()
            except ValueError as exc:
                raise GoogleSecopsApiError(
                    method,
                    path,
                    response.status_code,
                    "",
                    not_json_detail(response) or "the answer is not JSON",
                ) from exc
            return payload if isinstance(payload, dict) else {}

    # --- rules ---------------------------------------------------------------------

    @staticmethod
    def _rule(rule_id: str) -> str:
        return f"rules/{quote(rule_id, safe='')}"

    def verify(self, text: str) -> dict[str, Any]:
        return self.request("POST", ":verifyRuleText", body={"ruleText": text})

    def create(self, text: str, scope: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"text": text}
        if scope:
            body["scope"] = scope
        return self.request("POST", "rules", body=body)

    def get_rule(self, rule_id: str) -> dict[str, Any]:
        return self.request("GET", self._rule(rule_id), params={"view": "FULL"})

    def update_text(
        self, rule_id: str, text: str, etag: str | None, scope: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"text": text}
        mask = "text"
        if etag:
            body["etag"] = etag
        if scope:
            body["scope"] = scope
            mask = "text,scope"
        return self.request("PATCH", self._rule(rule_id), params={"updateMask": mask}, body=body)

    def get_deployment(self, rule_id: str) -> dict[str, Any]:
        return self.request("GET", f"{self._rule(rule_id)}/deployment")

    def update_deployment(self, rule_id: str, mask: str, body: Mapping[str, Any]) -> dict[str, Any]:
        return self.request(
            "PATCH", f"{self._rule(rule_id)}/deployment", params={"updateMask": mask}, body=body
        )

    def delete(self, rule_id: str) -> dict[str, Any]:
        """``DELETE rules/<id>``, never with ``force``: a rule's detections are kept."""
        return self.request("DELETE", self._rule(rule_id))

    # --- search --------------------------------------------------------------------

    def udm_search(self, params: Mapping[str, str]) -> dict[str, Any]:
        return self.request("GET", ":udmSearch", params=params)

    def scope_resource(self, scope_id: str | None) -> str | None:
        """``<instance>/dataAccessScopes/<id>`` for a tenant's ``data_access_scope``."""
        return f"{self.instance}/dataAccessScopes/{scope_id}" if scope_id else None
