"""A tenant that cannot be reached: DNS, a refused or reset connection, TLS, a timeout.

Live query validation reports it as the check's result for that tenant. It used
to escape the validator as a ``URLError`` or ``requests`` traceback with nothing
on stdout. Every other error still propagates, so a programming error is never
read as a network one.

A *read* timeout is not one on its own: the tenant took the request and one
query outlived the timeout (:func:`read_timeout`). Live validation fails that
query and goes on, and reports the tenant unreachable only after several in a
row.
"""

from __future__ import annotations

import re
import socket
import ssl
from collections.abc import Generator
from contextlib import contextmanager
from datetime import timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

import requests
import urllib3.exceptions

from opentide.core.errors import Errors

#: ``OSError`` itself is not listed: a missing file is not a network failure.
_TRANSPORT_ERRORS: tuple[type[BaseException], ...] = (
    URLError,
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    urllib3.exceptions.ConnectTimeoutError,
    urllib3.exceptions.ReadTimeoutError,
    ConnectionError,
    TimeoutError,
    socket.gaierror,
    socket.herror,
    ssl.SSLError,
)

#: Errors raised before the tenant took the request: the connection, DNS, TLS, a proxy.
#: A ``URLError`` is one too: ``urlopen`` wraps only the failures of connecting and
#: sending, and lets a timeout waiting for the answer through unwrapped.
_CONNECT_ERRORS: tuple[type[BaseException], ...] = (
    URLError,
    requests.exceptions.ConnectTimeout,
    requests.exceptions.ProxyError,
    requests.exceptions.SSLError,
    urllib3.exceptions.ConnectTimeoutError,
    socket.gaierror,
    ssl.SSLError,
)

#: Errors raised while waiting for the answer to a request the tenant took.
#: ``TimeoutError`` is ``socket.timeout``: ``urlopen`` raises it, unwrapped, when
#: the answer does not come in time ("The read operation timed out").
_READ_TIMEOUTS: tuple[type[BaseException], ...] = (
    requests.exceptions.ReadTimeout,
    urllib3.exceptions.ReadTimeoutError,
    TimeoutError,
)

#: HTTP statuses a gateway or proxy answers when the tenant behind it does not.
GATEWAY_STATUSES: dict[int, str] = {
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

#: Seconds after which an answer that is not the tenant's own is taken for a
#: gateway's that stopped waiting (a gateway's own timeout is commonly 30 to 60s).
SLOW_ANSWER_SECONDS = 30.0


#: Seconds a tenant has to accept a connection, and then to send each part of
#: its answer, when a request names no timeout of its own. Without one, a
#: tenant that accepts the connection and never answers held a deploy or a CI
#: job forever. Generous, because a live query check runs the query first.
DEFAULT_TIMEOUT = 120.0


def tenant_tls_verify(ssl_setting: object, *, platform: str, tenant: str) -> bool:
    """A tenant's ``ssl`` as the ``verify`` flag for every call made to it.

    Loading parses ``ssl`` to a boolean, but an ``ssl = "$VAR"`` whose
    variable is unset stays the literal ``$VAR``; ``requests`` would read that
    as the path of a CA bundle and fail with an unrelated ``OSError``.
    """
    if isinstance(ssl_setting, bool):
        return ssl_setting
    if isinstance(ssl_setting, str) and ssl_setting.startswith("$"):
        raise ValueError(
            f"{platform} tenant {tenant!r} setup: ssl is unset ({ssl_setting}). "
            "Set that environment variable to true or false before a live check."
        )
    raise ValueError(
        f"{platform} tenant {tenant!r} setup: ssl must be true or false, got {ssl_setting!r}"
    )


class TenantSession(requests.Session):
    """A session whose every request verifies TLS as the tenant's ``ssl`` says.

    ``requests`` lets ``REQUESTS_CA_BUNDLE`` or ``CURL_CA_BUNDLE`` replace a
    session's ``verify`` for any request that does not pass its own
    (psf/requests#3829), so with a corporate CA bundle exported, ``ssl =
    false`` quietly verified again and a self-signed tenant failed. A request
    that names no ``verify`` takes the session's here before the environment is
    consulted; with ``verify`` true the exported bundle still applies, as it
    should.

    A request sent without a ``timeout`` gets :data:`DEFAULT_TIMEOUT`, where
    ``requests`` itself would wait forever.
    """

    def __init__(self, verify: bool) -> None:
        super().__init__()
        self.verify = verify

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        # ``Session.request`` passes timeout=None for a call that names none.
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = DEFAULT_TIMEOUT
        return super().send(request, **kwargs)

    def merge_environment_settings(
        self,
        url: str,
        proxies: dict[str, str] | None,
        stream: bool | None,
        verify: bool | str | None,
        cert: str | tuple[str, str] | None,
    ) -> dict[str, Any]:
        if verify is None:
            verify = self.verify
        return super().merge_environment_settings(url, proxies, stream, verify, cert)


class TenantUnreachableError(Errors.TenantConnectionError):
    """A live check could not reach *host*, the address of *tenant* on *platform*.

    A :class:`Errors.TenantConnectionError`, so code that catches the documented
    class around a validator catches this too. *reason* replaces the error's
    text in the message; *timeouts* counts the queries in a row that got no
    answer, when that is why the tenant is reported unreachable.
    """

    def __init__(
        self,
        platform: str,
        tenant: str,
        host: str,
        error: BaseException,
        *,
        reason: str | None = None,
        timeouts: int = 0,
    ) -> None:
        self.platform = platform
        self.tenant = tenant
        self.host = host
        self.error = error
        self.timeouts = timeouts
        super().__init__(f"Cannot reach {platform} tenant '{tenant}' at {host}: {reason or error}")


class GatewayTimeoutError(TimeoutError):
    """A gateway or proxy in front of the tenant answered for it, instead of its API.

    An HTTP 502, 503 or 504, or a page that is not the API's after a slow
    request: the request reached the gateway, which gave up waiting for the
    tenant. A ``TimeoutError``, so a live check fails that query
    (:func:`read_timeout`) rather than the whole tenant.
    """

    def __init__(self, message: str, *, status: int, elapsed: float | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.elapsed = elapsed


def gateway_answer(status: int, elapsed: float | None = None) -> str | None:
    """Why an answer that is not the tenant's API is a gateway's, or ``None`` when it is not.

    *status* is the answer's HTTP status and *elapsed* the seconds the request
    took, when they are known.
    """
    name = GATEWAY_STATUSES.get(status)
    if name is not None:
        return (
            f"HTTP {status} {name} is what a gateway or proxy in front of the tenant answers "
            "when the tenant does not answer it in time, so the url and port are not at fault "
            "when other requests to the same address succeed"
        )
    if elapsed is not None and elapsed >= SLOW_ANSWER_SECONDS:
        return (
            f"it came after {elapsed:.0f}s, as from a gateway or proxy in front of the tenant "
            "that stopped waiting for it"
        )
    return None


_HTML_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def page_title(body: bytes) -> str | None:
    """The ``<title>`` of an HTML page, or ``None``."""
    found = _HTML_TITLE.search(body)
    if found is None:
        return None
    return " ".join(found.group(1).decode(errors="replace").split()) or None


def describe_answer(
    status: int, body: bytes, *, content_type: str | None = None, elapsed: float | None = None
) -> str:
    """One line on an answer that is not the API's JSON: its status, its body, a gateway's reading.

    *elapsed* is the seconds the request took; a slow answer that is not the
    API's is read as a gateway's (:func:`gateway_answer`).
    """
    kind = (content_type or "").split(";")[0].strip().lower()
    head = body.lstrip()[:15].lower()
    if kind == "text/html" or head.startswith((b"<!doctype html", b"<html")):
        title = page_title(body)
        text = f"HTTP {status} with an HTML page" + (f" titled {title!r}" if title else "")
    elif not body.strip():
        text = f"HTTP {status} with an empty body"
    else:
        snippet = " ".join(body[:200].decode(errors="replace").split())
        text = f"HTTP {status} with a body that is not JSON ({snippet!r})"
    hint = gateway_answer(status, elapsed)
    return f"{text}: {hint}" if hint else text


def not_json_detail(response: Any) -> str | None:
    """:func:`describe_answer` for a ``requests`` *response* that is not JSON, else ``None``."""
    try:
        response.json()
    except ValueError:
        pass
    else:
        return None
    headers = getattr(response, "headers", None) or {}
    elapsed = getattr(response, "elapsed", None)
    body = getattr(response, "content", None)
    if not isinstance(body, bytes):
        body = str(getattr(response, "text", "") or "").encode()
    return describe_answer(
        int(response.status_code),
        body,
        content_type=str(headers.get("Content-Type") or "") or None,
        elapsed=elapsed.total_seconds() if isinstance(elapsed, timedelta) else None,
    )


def _links(exc: BaseException) -> Generator[BaseException, None, None]:
    """*exc* and the errors it wraps, outermost first.

    A vendor SDK may wrap the failure: Carbon Black Cloud raises its own
    ``ConnectionError`` with the ``requests`` error as ``original_exception``,
    Azure its ``ServiceResponseError`` with it as ``inner_exception``. A
    ``requests`` error carries urllib3's as its first argument, and urllib3's
    ``MaxRetryError`` the last attempt's as its ``reason``: that is how a
    read timeout the retries did not clear reaches a caller, as a
    ``requests.ConnectionError``.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        yield current
        seen.add(id(current))
        inner: object = None
        for attribute in ("original_exception", "inner_exception"):
            inner = getattr(current, attribute, None)
            if isinstance(inner, BaseException):
                break
        if not isinstance(inner, BaseException) and isinstance(
            current, requests.exceptions.RequestException
        ):
            inner = current.args[0] if current.args else None
        if isinstance(current, urllib3.exceptions.MaxRetryError):
            inner = current.reason
        current = inner if isinstance(inner, BaseException) else None


def transport_error(exc: BaseException) -> BaseException | None:
    """The transport failure behind *exc*, or ``None`` when *exc* is anything else.

    An HTTP error status is a response, so it is not one.
    """
    for link in _links(exc):
        if isinstance(link, _TRANSPORT_ERRORS) and not isinstance(link, HTTPError):
            return link
    return None


def read_timeout(exc: BaseException) -> BaseException | None:
    """The read timeout behind *exc*: the tenant took the request and sent no answer in time.

    ``None`` for anything else, a connect timeout included: a tenant that
    does not take the connection is unreachable, one that is slow to answer
    one query is not. Every wrapped error is read first, so a wrapper named
    for timeouts around a connect timeout is still a connect failure.
    """
    links = list(_links(exc))
    if any(isinstance(link, _CONNECT_ERRORS) for link in links):
        return None
    return next((link for link in links if isinstance(link, _READ_TIMEOUTS)), None)


def _origin(url: str) -> str:
    """``scheme://host[:port]`` of *url*, without credentials, path or query."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return url
    return f"{parts.scheme}://{parts.netloc.rpartition('@')[2]}"


@contextmanager
def reaching_tenant(platform: str, tenant: str, host: str) -> Generator[None, None, None]:
    """Raise :class:`TenantUnreachableError` for a transport failure inside the block.

    *host* is the tenant's configured address. A ``requests`` error records the
    URL it failed on, which names the host when a tenant has two (Elastic's
    Kibana and Elasticsearch).
    """
    try:
        yield
    except Exception as exc:
        error = transport_error(exc)
        if error is None:
            raise
        url = getattr(getattr(error, "request", None), "url", None)
        address = _origin(url if isinstance(url, str) and url else host)
        raise TenantUnreachableError(platform, tenant, address, error) from exc
