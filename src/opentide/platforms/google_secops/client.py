"""Chronicle API v1 client for one Google SecOps instance (google-secops-1.0).

Every request goes to ``<endpoint>/v1/projects/<project>/locations/<location>/
instances/<instance>`` with an OAuth 2.0 access token for the
``cloud-platform`` scope: from the service-account key the tenant's
``credentials`` variable holds (a JSON document or the path to one), or from
Application Default Credentials. Requests run on a
:class:`~opentide.platforms.transport.TenantSession`, so TLS follows the
tenant's ``ssl`` and nothing waits forever.

The token is applied as google-auth applies it (:meth:`Credentials.apply`), so
user credentials from Application Default Credentials also send their quota
project (``x-goog-user-project``). A token that cannot be obtained is a
:class:`GoogleSecopsTokenError`: no request was sent, and the tenant stops.

HTTP 401 and 403 stop the tenant (:class:`GoogleSecopsTenantError`). HTTP 429,
and 503 on any call but a create, are waited out: ``Retry-After`` (at most
300 seconds), else the ``RetryInfo.retryDelay`` of ``error.details``, else 5,
15 and 60 seconds, and the same request is sent again, at most three times;
then the call fails. Any other error is a :class:`GoogleSecopsApiError` with
Google's ``error.status`` and ``error.message``. No transport-level retry is
mounted, and ``POST rules`` is never resent after a 5xx or no answer: the rule
may exist (``google_secops_create_unconfirmed``).
"""

from __future__ import annotations

import json
import re
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
#: Waits after a 429 or 503 whose answer names none (no ``Retry-After``, no
#: ``RetryInfo``). A request is resent at most this many times, whether or not
#: Google names the wait; then the call fails.
BACKOFF = (5.0, 15.0, 60.0)
#: The most one named wait (``Retry-After`` or ``RetryInfo``) is honoured for, in seconds.
MAX_RETRY_AFTER = 300.0
#: ``error.details`` entry that names how long to wait.
RETRY_INFO = "type.googleapis.com/google.rpc.RetryInfo"
_DURATION = re.compile(r"\s*(\d+(?:\.\d+)?)s\s*")


class Credentials(Protocol):
    """What the client needs of a ``google.auth`` credentials object."""

    token: str | None

    @property
    def valid(self) -> bool: ...

    def refresh(self, request: Any) -> None: ...

    def apply(self, headers: dict[str, str], token: str | None = None) -> None: ...


class GoogleSecopsTenantError(RuntimeError):
    """The instance cannot take any request: refused or missing credentials."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class GoogleSecopsTokenError(GoogleSecopsTenantError):
    """No access token: Google refused the credentials, or its token endpoint did not answer.

    Raised before the request it was for was sent, so a create that hits it
    cannot have happened.
    """

    def __init__(self, message: str) -> None:
        super().__init__("google_secops_tenant_unauthorized", message)


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
    def server_error(self) -> bool:
        return self.http_status >= 500

    @property
    def refused_delete(self) -> bool:
        """A ``DELETE`` Google refused: any 4xx but 401, 403, 404 and 429.

        Google does not document which status a rule with detections or
        retrohunts gets (google-secops-1.0, Deletion).
        """
        return 400 <= self.http_status < 500 and self.http_status not in (401, 403, 404, 429)


def duration_seconds(value: object) -> float | None:
    """A protobuf ``Duration`` in JSON (``"1800s"``, ``"1800.000s"``) in seconds, or ``None``."""
    found = _DURATION.fullmatch(value) if isinstance(value, str) else None
    return float(found.group(1)) if found else None


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
    """The wait the answer names: ``Retry-After``, else ``RetryInfo.retryDelay``; capped."""
    value = response.headers.get("Retry-After")
    if value is not None:
        try:
            return min(max(float(value), 0.0), MAX_RETRY_AFTER)
        except ValueError:
            pass
    try:
        payload = response.json()
    except ValueError:
        return None
    error = payload.get("error") if isinstance(payload, dict) else None
    details = error.get("details") if isinstance(error, dict) else None
    for detail in details if isinstance(details, list) else []:
        if isinstance(detail, dict) and detail.get("@type") == RETRY_INFO:
            seconds = duration_seconds(detail.get("retryDelay"))
            if seconds is not None:
                return min(seconds, MAX_RETRY_AFTER)
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

    def _authorise(self, headers: dict[str, str]) -> None:
        """Put the access token, and a user credential's quota project, on *headers*.

        Raises :class:`GoogleSecopsTokenError` when no token can be obtained.
        """
        from google.auth.exceptions import RefreshError, TransportError

        if not self._credentials.valid:
            from google.auth.transport.requests import Request

            try:
                self._credentials.refresh(Request(session=self.session))
            except RefreshError as exc:
                raise GoogleSecopsTokenError(
                    f"tenant {self.tenant}: Google refused the credentials ({exc})"
                ) from exc
            except (TransportError, requests.RequestException) as exc:
                raise GoogleSecopsTokenError(
                    f"tenant {self.tenant}: Google's token endpoint did not answer ({exc})"
                ) from exc
        if not self._credentials.token:
            raise GoogleSecopsTokenError(
                f"tenant {self.tenant}: the credentials gave no access token"
            )
        self._credentials.apply(headers)

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | None = None,
        resend_unavailable: bool = True,
    ) -> dict[str, Any]:
        """Send one request and return its JSON answer.

        *path* is relative to the instance resource: ``"rules"``,
        ``":verifyRuleText"``. A 429 is resent; a 503 only with
        *resend_unavailable*. Raises :class:`GoogleSecopsTenantError`,
        :class:`GoogleSecopsApiError`, or a :class:`requests.RequestException`
        when the request got no answer.
        """
        url = self.base + path if path.startswith(":") else f"{self.base}/{path}"
        resent = {429, 503} if resend_unavailable else {429}
        retries = 0
        while True:
            headers: dict[str, str] = {}
            self._authorise(headers)
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
            if response.status_code in resent and retries < len(BACKOFF):
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
        """``POST rules``, never resent after a 5xx: the rule may have been created.

        A 429 is resent: Google did not execute it.
        """
        body: dict[str, Any] = {"text": text}
        if scope:
            body["scope"] = scope
        return self.request("POST", "rules", body=body, resend_unavailable=False)

    def get_rule(self, rule_id: str) -> dict[str, Any]:
        return self.request("GET", self._rule(rule_id), params={"view": "FULL"})

    def update_text(self, rule_id: str, text: str, etag: str | None) -> dict[str, Any]:
        body: dict[str, Any] = {"text": text}
        if etag:
            body["etag"] = etag
        return self.request("PATCH", self._rule(rule_id), params={"updateMask": "text"}, body=body)

    def update_scope(self, rule_id: str, scope: str, etag: str | None) -> dict[str, Any]:
        """``PATCH rules/<id>?updateMask=scope``; an empty *scope* makes the rule global."""
        body: dict[str, Any] = {"scope": scope}
        if etag:
            body["etag"] = etag
        return self.request("PATCH", self._rule(rule_id), params={"updateMask": "scope"}, body=body)

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

    def scope_resource(self, scope: str | None) -> str | None:
        """The ``scope`` for a tenant's ``data_access_scope``: an id or a full resource name.

        A full name (``projects/…/dataAccessScopes/<id>``) is used as given; an
        id becomes ``<instance>/dataAccessScopes/<id>``.
        """
        if not scope:
            return None
        scope = scope.strip().strip("/")
        if "/dataAccessScopes/" in f"/{scope}":
            return scope
        return f"{self.instance}/dataAccessScopes/{scope}"
