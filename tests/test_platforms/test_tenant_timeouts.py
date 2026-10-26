"""A tenant that accepts a connection and never answers fails the call instead of hanging it.

Neither ``requests`` nor ``urllib`` has a default timeout. Defender,
SentinelOne, CrowdStrike and HarfangLab sessions, the Entra ID and CrowdStrike
token requests, and Splunk's handler waited forever, and so did the CI job.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest
import requests

from opentide.platforms import transport
from opentide.platforms.transport import DEFAULT_TIMEOUT, TenantSession

_PROXY_VARIABLES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
)


@pytest.fixture
def silent_tenant(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """``http://`` address of a server that accepts connections and never answers."""
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        listener.settimeout(0.1)
        while not stop.is_set():
            try:
                held.append(listener.accept()[0])
            except OSError:
                continue

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        stop.set()
        thread.join()
        for connection in held:
            connection.close()
        listener.close()


def _raised(call: Callable[[], object], *, within: float = 10) -> BaseException | None:
    """What *call* raised; fails the test, instead of hanging it, if it is still waiting."""
    outcome: list[BaseException | None] = []

    def run() -> None:
        try:
            call()
        except BaseException as exc:
            outcome.append(exc)
        else:
            outcome.append(None)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(within)
    if thread.is_alive():
        pytest.fail(f"still waiting for the tenant after {within} s: the call has no timeout")
    return outcome[0]


def test_the_default_is_finite() -> None:
    assert 0 < DEFAULT_TIMEOUT <= 300


def test_a_tenant_session_times_out_a_tenant_that_never_answers(
    silent_tenant: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport, "DEFAULT_TIMEOUT", 0.2)
    error = _raised(lambda: TenantSession(verify=True).get(silent_tenant))
    assert isinstance(error, requests.exceptions.ReadTimeout)


def test_a_request_keeps_its_own_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Elastic (30 s) and Sentinel (60 s) pass their own; the default must not replace it."""
    sent: list[object] = []

    def send(_session: requests.Session, _request: object, **kwargs: Any) -> object:
        sent.append(kwargs["timeout"])
        return SimpleNamespace()

    monkeypatch.setattr(requests.Session, "send", send)
    session = TenantSession(verify=True)
    session.get("https://tenant.example")
    session.post("https://tenant.example", timeout=30)
    session.request("GET", "https://tenant.example", timeout=(5, 60))

    assert sent == [DEFAULT_TIMEOUT, 30, (5, 60)]


def test_the_splunk_handler_times_out_a_tenant_that_never_answers(
    silent_tenant: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.platforms.splunk import client as splunk_client

    monkeypatch.setattr(splunk_client, "DEFAULT_TIMEOUT", 0.2)
    handle = splunk_client.request_handler(verify=False)
    url = f"{silent_tenant}/services/server/info"
    error = _raised(lambda: handle(url, {"method": "GET", "headers": []}))
    assert isinstance(error, TimeoutError)


@pytest.mark.parametrize(
    ("module", "service_class", "status"),
    [
        ("opentide.platforms.crowdstrike.client", "CrowdstrikeService", 201),
        ("opentide.platforms.defender_for_endpoint.client", "DefenderForEndpointService", 200),
    ],
)
def test_token_requests_carry_a_timeout(
    monkeypatch: pytest.MonkeyPatch, module: str, service_class: str, status: int
) -> None:
    import importlib

    client = importlib.import_module(module)
    seen: dict[str, object] = {}

    def post(**kwargs: object) -> SimpleNamespace:
        seen.update(kwargs)
        return SimpleNamespace(status_code=status, json=lambda: {"access_token": "token"})

    monkeypatch.setattr(client.requests, "post", post)
    cls = getattr(client, service_class)
    service = cls.__new__(cls)
    service.tenant_config = SimpleNamespace(name="Primary")
    service.verify = True
    service.OAUTH_TOKEN_ENDPOINT = "https://login.example/{tenant_id}/oauth2/token"
    if service_class == "CrowdstrikeService":
        service._get_access_token("id", "secret")
    else:
        service._connect_to_tenant("id", "tenant", "secret")

    assert seen["timeout"] == DEFAULT_TIMEOUT
