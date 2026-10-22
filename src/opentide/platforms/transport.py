"""A tenant that cannot be reached: DNS, a refused or reset connection, TLS, a timeout.

Live query validation reports it as the check's result for that tenant. It used
to escape the validator as a ``URLError`` or ``requests`` traceback with nothing
on stdout. Every other error still propagates, so a programming error is never
read as a network one.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

import requests

from opentide.core.errors import Errors

#: ``OSError`` itself is not listed: a missing file is not a network failure.
_TRANSPORT_ERRORS: tuple[type[BaseException], ...] = (
    URLError,
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    ConnectionError,
    TimeoutError,
    socket.gaierror,
    socket.herror,
    ssl.SSLError,
)


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
    class around a validator catches this too.
    """

    def __init__(self, platform: str, tenant: str, host: str, error: BaseException) -> None:
        self.platform = platform
        self.tenant = tenant
        self.host = host
        self.error = error
        super().__init__(f"Cannot reach {platform} tenant '{tenant}' at {host}: {error}")


def transport_error(exc: BaseException) -> BaseException | None:
    """The transport failure behind *exc*, or ``None`` when *exc* is anything else.

    An HTTP error status is a response, so it is not one. A vendor SDK may wrap
    the failure: Carbon Black Cloud raises its own ``ConnectionError`` with the
    ``requests`` error as ``original_exception``.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, _TRANSPORT_ERRORS) and not isinstance(current, HTTPError):
            return current
        seen.add(id(current))
        inner = getattr(current, "original_exception", None)
        current = inner if isinstance(inner, BaseException) else None
    return None


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
