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
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

import requests

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


class TenantUnreachableError(Exception):
    """A live check could not reach *host*, the address of *tenant* on *platform*."""

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
