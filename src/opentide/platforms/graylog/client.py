"""REST client for Graylog event definitions and searches (graylog-1.0, Deploy).

Every request goes to ``<url>/api/...`` with ``Accept: application/json``,
``X-Requested-By: opentide`` and HTTP Basic ``<token>:token``, on a
:class:`~opentide.platforms.transport.TenantSession` (the tenant's ``ssl``, a
timeout on every call). A 401 stops the tenant (:class:`GraylogTenantError`);
any other answer that is not 2xx is a :class:`GraylogApiError` for the rule.

No transport-level retry is mounted: a create that got no answer is never sent
again, because titles are not unique and a retry may create a second definition.
"""

from __future__ import annotations

import re
from typing import Any

import requests

from opentide.core.environment import reject_unsubstituted_placeholders
from opentide.platforms.graylog.compile import (
    MINIMUM_VERSION,
    VALIDATE_PATH,
    Version,
    create_path,
    delete_path,
    parse_version,
    update_path,
)
from opentide.platforms.transport import TenantSession, not_json_detail

SYSTEM_PATH = "/api/system"
MESSAGES_PATH = "/api/search/messages"
REQUESTED_BY = "opentide"

_IMMUTABLE = re.compile(
    r"immutable entity cannot be modified|non-deletable entity cannot be deleted", re.IGNORECASE
)
_IN_USE = re.compile(r"\bin use\b|\bdepend|\breferenced\b|\bused by\b", re.IGNORECASE)
_DEFINITION_ID = re.compile(r"[0-9a-fA-F]{24}")


class GraylogTenantError(RuntimeError):
    """The tenant cannot take any rule: a refused token, or an unsupported version."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class GraylogApiError(RuntimeError):
    """A request failed for this rule only: its status and Graylog's own message."""

    def __init__(
        self,
        method: str,
        path: str,
        status: int,
        message: str,
        errors: dict[str, list[str]] | None = None,
    ) -> None:
        self.method = method
        self.path = path
        self.status = status
        self.message = message
        self.errors = errors or {}
        super().__init__(f"{method} {path}: HTTP {status}: {self.detail}")

    @property
    def detail(self) -> str:
        """Graylog's message, with each refused field's messages."""
        parts = [self.message] if self.message else []
        parts.extend(
            f"{name}: {'; '.join(messages)}" for name, messages in sorted(self.errors.items())
        )
        return " | ".join(parts) or "no detail given"

    @property
    def not_found(self) -> bool:
        return self.status == 404

    @property
    def forbidden(self) -> bool:
        return self.status == 403

    @property
    def immutable(self) -> bool:
        """ "Immutable entity cannot be modified" or "Non-deletable entity cannot be deleted"."""
        return bool(_IMMUTABLE.search(self.detail))

    @property
    def in_use(self) -> bool:
        """A ``DELETE`` refused because another definition depends on this one."""
        return (
            self.method == "DELETE"
            and self.status in (400, 409)
            and bool(_IN_USE.search(self.detail))
        )

    @property
    def invalid(self) -> bool:
        """A 400 with ``{"errors": {<field>: [<message>]}}``: Graylog refused the body."""
        return self.status == 400 and bool(self.errors)


def _errors(payload: Any) -> dict[str, list[str]]:
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if not isinstance(errors, dict):
        return {}
    found: dict[str, list[str]] = {}
    for name, messages in errors.items():
        items = messages if isinstance(messages, list) else [messages]
        found[str(name)] = [str(item) for item in items]
    return found


def _message(response: requests.Response) -> tuple[str, dict[str, list[str]]]:
    try:
        payload = response.json()
    except ValueError:
        return not_json_detail(response) or f"HTTP {response.status_code}", {}
    message = payload.get("message") if isinstance(payload, dict) else None
    return (str(message) if message else ""), _errors(payload)


#: ``error_type`` values Graylog reports at WARNING level, each with its opentide code.
WARNING_TYPES: dict[str, str] = {
    "UNKNOWN_FIELD": "graylog_unknown_field",
    "INVALID_VALUE_TYPE": "graylog_value_type",
    "INVALID_OPERATOR": "graylog_query_warning",
}
QUERY_WARNING = "graylog_query_warning"
QUERY_INVALID = "graylog_query_invalid"


def explanation_text(explanation: Any) -> str:
    """One explanation as a line: its title and message, at Graylog's line and column."""
    if not isinstance(explanation, dict):
        return str(explanation)
    title = str(explanation.get("error_title") or explanation.get("error_type") or "").strip()
    message = str(explanation.get("error_message") or "").strip()
    text = ": ".join(part for part in (title, message) if part) or "no detail given"
    line, column = explanation.get("begin_line"), explanation.get("begin_column")
    if isinstance(line, int) and isinstance(column, int):
        text += f" (line {line}, column {column})"
    return text


def read_verdict(payload: dict[str, Any]) -> tuple[list[str], list[tuple[str, str]]]:
    """``(errors, warnings)`` of a ``/api/search/validate`` answer.

    ``status: ERROR`` makes its explanations errors, but for the types Graylog
    reports as warnings (``UNKNOWN_FIELD``, ``INVALID_VALUE_TYPE``); an ERROR
    with no other explanation is one error. A WARNING or INFO explanation is a
    ``(code, text)`` warning: ``graylog_unknown_field``, ``graylog_value_type``,
    else ``graylog_query_warning``.
    """
    status = str(payload.get("status") or "OK").upper()
    raw = payload.get("explanations")
    explanations = raw if isinstance(raw, list) else []
    errors: list[str] = []
    warnings: list[tuple[str, str]] = []
    for explanation in explanations:
        kind = str(explanation.get("error_type") or "") if isinstance(explanation, dict) else ""
        if status == "ERROR" and kind not in WARNING_TYPES:
            errors.append(explanation_text(explanation))
        else:
            warnings.append((WARNING_TYPES.get(kind, QUERY_WARNING), explanation_text(explanation)))
    if status == "ERROR" and not errors:
        errors.append("Graylog reports the query as ERROR")
    return errors, warnings


def returned_id(payload: Any) -> str | None:
    """The 24-hex ``id`` a create answered, lower-cased, or ``None``."""
    value = payload.get("id") if isinstance(payload, dict) else None
    if isinstance(value, str) and _DEFINITION_ID.fullmatch(value.strip()):
        return value.strip().lower()
    return None


class GraylogClient:
    """Event definitions and searches on one Graylog tenant."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        tenant: str,
        verify_ssl: bool = True,
        timeout: float = 30,
    ) -> None:
        # An unset $GRAYLOG_TOKEN stays the literal placeholder: refuse it rather
        # than send it as a token.
        reject_unsubstituted_placeholders(url, token, client="Graylog")
        self.base = url.rstrip("/")
        self.tenant = tenant
        self.timeout = timeout
        self.session = TenantSession(verify=verify_ssl)
        self.session.auth = (token, "token")
        self.session.headers.update({"Accept": "application/json", "X-Requested-By": REQUESTED_BY})
        self._version: Version | None = None

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> requests.Response:
        """Send one request; a 2xx answer is returned, any other raises.

        Raises :class:`GraylogTenantError` on 401, :class:`GraylogApiError` on
        any other status that is not 2xx, and lets a
        :class:`requests.RequestException` (no answer) through.
        """
        response = self.session.request(
            method,
            self.base + path,
            json=body,
            timeout=timeout or self.timeout,
            allow_redirects=False,
        )
        if response.status_code == 401:
            raise GraylogTenantError(
                "graylog_tenant_unauthorized",
                f"tenant {self.tenant} refused the access token: HTTP 401",
            )
        if not 200 <= response.status_code < 300:
            message, errors = _message(response)
            raise GraylogApiError(method, path, response.status_code, message, errors)
        return response

    def _json(self, response: requests.Response, method: str, path: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise GraylogApiError(
                method, path, response.status_code, not_json_detail(response) or "not JSON"
            ) from exc

    # --- the server -------------------------------------------------------------------

    def version(self) -> Version:
        """The server version (``GET /api/system``), read once per client.

        Raises :class:`GraylogTenantError` ``graylog_version_unsupported`` for a
        version below 6.3, or none.
        """
        if self._version is not None:
            return self._version
        payload = self._json(self.request("GET", SYSTEM_PATH), "GET", SYSTEM_PATH)
        raw = payload.get("version") if isinstance(payload, dict) else None
        version = parse_version(raw)
        if version is None or version < MINIMUM_VERSION:
            shown = repr(raw) if raw is not None else "no version"
            raise GraylogTenantError(
                "graylog_version_unsupported",
                f"tenant {self.tenant} runs Graylog {shown}; opentide deploys to Graylog 6.3 "
                "and later",
            )
        self._version = version
        return version

    # --- queries ----------------------------------------------------------------------

    def validate_query(
        self, body: dict[str, Any], *, timeout: float | None = None
    ) -> dict[str, Any]:
        """``POST /api/search/validate``: Graylog's verdict on a query, nothing saved."""
        response = self.request("POST", VALIDATE_PATH, body, timeout=timeout)
        payload = self._json(response, "POST", VALIDATE_PATH)
        if not isinstance(payload, dict):
            raise GraylogApiError("POST", VALIDATE_PATH, response.status_code, "not an object")
        return payload

    def search_messages(self, body: dict[str, Any], *, timeout: float | None = None) -> Any:
        """``POST /api/search/messages``: rows for a query, read-only."""
        response = self.request("POST", MESSAGES_PATH, body, timeout=timeout)
        return self._json(response, "POST", MESSAGES_PATH)

    # --- event definitions ------------------------------------------------------------

    def create(self, body: dict[str, Any]) -> Any:
        """``POST /api/events/definitions?schedule=true``; the answer's JSON.

        ``None`` for a 2xx whose body is not JSON (empty, or a proxy's page): the
        definition may exist, so the caller reports it unconfirmed, never as a
        failed request that a later run would create again.
        """
        path = create_path()
        response = self.request("POST", path, body)
        try:
            return response.json()
        except ValueError:
            return None

    def update(self, definition_id: str, body: dict[str, Any], *, enabled: bool) -> None:
        """``PUT /api/events/definitions/{id}?schedule=<enabled>`` with the whole definition."""
        self.request("PUT", update_path(definition_id, enabled=enabled), body)

    def delete(self, definition_id: str) -> None:
        """``DELETE /api/events/definitions/{id}``: any 2xx, 204 for an id Graylog does not have."""
        self.request("DELETE", delete_path(definition_id))
