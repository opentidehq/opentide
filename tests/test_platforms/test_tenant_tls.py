"""Every platform applies its tenant's ``ssl`` to every call it makes, token requests included.

Each client runs against the self-signed HTTPS stand-in from
``tests.splunk_support``. Its public hosts (``api.crowdstrike.com``,
``login.microsoftonline.com``, ...) are rewritten to the stand-in at
``requests.Session.request``, which ``requests.post`` goes through too, so the
TLS handshake and the ``verify`` flag are the real ones: ``ssl = false`` must
reach the stand-in, ``ssl = true`` must refuse its certificate.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
import requests
from tests.splunk_support import SplunkStandIn, serve_splunk

from opentide.platforms.transport import tenant_tls_verify

pytest.importorskip("cryptography")


@pytest.fixture
def stand_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[SplunkStandIn]:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    with serve_splunk(tmp_path) as server:
        original = requests.Session.request

        def rerouted(self: requests.Session, method: str, url: str, *args: Any, **kwargs: Any):
            parts = urllib.parse.urlsplit(url)
            local = parts._replace(scheme="https", netloc=f"localhost:{server.port}")
            return original(self, method, urllib.parse.urlunsplit(local), *args, **kwargs)

        monkeypatch.setattr(requests.Session, "request", rerouted)
        yield server


def _tenant(ssl: object, **setup: object) -> SimpleNamespace:
    return SimpleNamespace(name="Primary", setup=SimpleNamespace(ssl=ssl, **setup))


def _reaches(call: Callable[[], object]) -> None:
    """Run *call*; the stand-in answers 404, so only a TLS failure matters."""
    try:
        call()
    except requests.exceptions.SSLError:
        raise
    except Exception:
        pass


def _crowdstrike(ssl: object):
    from opentide.platforms.crowdstrike.client import CrowdstrikeService

    service = CrowdstrikeService(_tenant(ssl, api="EU-1", client_id="id", client_secret="secret"))
    return service, lambda: service.delete_detection_rule("rule-1")


def _defender(ssl: object):
    from opentide.platforms.defender_for_endpoint.client import DefenderForEndpointService

    service = DefenderForEndpointService(
        _tenant(ssl, tenant_id="tenant", client_id="id", client_secret="secret")
    )
    return service, lambda: service.delete_detection_rule(1)


def _harfanglab(ssl: object):
    from opentide.platforms.harfanglab import client

    # The corpus has no HarfangLab configuration; the constructor reads only its identifier.
    platform = SimpleNamespace(platform=SimpleNamespace(identifier="harfanglab"))
    registry = SimpleNamespace(
        Configurations=SimpleNamespace(Systems=SimpleNamespace(HarfangLab=platform))
    )
    with patch.object(client, "Opentide", registry):
        service = client.HarfangLabService(
            _tenant(ssl, url="https://hurukai.example", api_token="token")
        )
    return service, lambda: service.delete_sigma_rule("rule-1")


def _sentinel_one(ssl: object):
    from opentide.platforms.sentinel_one.client import SentinelOneService

    service = SentinelOneService(
        _tenant(ssl, url="https://s1.example", api_token="token", account_id=1, site_id=None)
    )
    return service, lambda: service.delete_detection_rule(1)


def _elastic(ssl: object):
    from opentide.platforms.elastic.client import ElasticClient

    tenant = _tenant(ssl)
    verify = tenant_tls_verify(tenant.setup.ssl, platform="elastic", tenant=tenant.name)
    client = ElasticClient(url="https://kibana.example", api_key="key", verify_ssl=verify)
    return client, lambda: client.get_rule("rule-1")


_CLIENTS = {
    "crowdstrike": _crowdstrike,
    "defender_for_endpoint": _defender,
    "harfanglab": _harfanglab,
    "sentinel_one": _sentinel_one,
    "elastic": _elastic,
}


@pytest.mark.usefixtures("tide_corpus_repo")
@pytest.mark.parametrize("platform", list(_CLIENTS))
def test_ssl_false_reaches_a_self_signed_tenant(platform: str, stand_in: SplunkStandIn) -> None:
    service, call = _CLIENTS[platform](False)
    _reaches(call)

    assert service.session.verify is False
    assert len(stand_in.requests) >= 1
    if platform in ("crowdstrike", "defender_for_endpoint"):
        # The token request carries the tenant's ssl too.
        assert stand_in.requests[0][1].endswith("token")
        assert len(stand_in.requests) >= 2


@pytest.mark.usefixtures("tide_corpus_repo")
@pytest.mark.parametrize("platform", list(_CLIENTS))
def test_ssl_true_refuses_a_self_signed_tenant(platform: str, stand_in: SplunkStandIn) -> None:
    with pytest.raises(requests.exceptions.SSLError):
        _service, call = _CLIENTS[platform](True)
        call()
    assert stand_in.requests == []


@pytest.mark.usefixtures("tide_corpus_repo")
@pytest.mark.parametrize("platform", list(_CLIENTS))
def test_an_unset_ssl_placeholder_is_refused_before_any_request(
    platform: str, stand_in: SplunkStandIn
) -> None:
    with pytest.raises(ValueError, match=r"tenant 'Primary' setup: ssl is unset \(\$TENANT_SSL\)"):
        _service, call = _CLIENTS[platform]("$TENANT_SSL")
        call()
    assert stand_in.requests == []


@pytest.mark.parametrize("ssl", [False, True])
def test_sentinel_applies_ssl_to_the_token_request_and_arm(
    monkeypatch: pytest.MonkeyPatch, ssl: bool
) -> None:
    import azure.identity

    from opentide.platforms.sentinel.client import SentinelService

    seen: dict[str, object] = {}

    def credential(*args: object, **kwargs: object) -> object:
        seen.update(kwargs)
        return object()

    monkeypatch.setattr(azure.identity, "ClientSecretCredential", credential)
    tenant = _tenant(
        ssl,
        azure_tenant_id="tenant",
        azure_client_id="id",
        azure_client_secret="secret",
        azure_subscription_id="subscription",
    )
    client = SentinelService(tenant).connect()

    assert seen["connection_verify"] is ssl
    assert client.alert_rules._session.verify is ssl


def test_sentinel_refuses_an_unset_ssl_placeholder() -> None:
    from opentide.platforms.sentinel.client import SentinelService

    tenant = _tenant(
        "$TENANT_SSL",
        azure_tenant_id="tenant",
        azure_client_id="id",
        azure_client_secret="secret",
        azure_subscription_id="subscription",
    )
    with pytest.raises(ValueError, match=r"sentinel tenant 'Primary' setup: ssl is unset"):
        SentinelService(tenant).connect()


@pytest.mark.parametrize("ssl", [False, True])
def test_carbon_black_passes_ssl_to_the_sdk(monkeypatch: pytest.MonkeyPatch, ssl: bool) -> None:
    import cbc_sdk.rest_api

    from opentide.platforms.carbon_black.client import CarbonBlackCloudService

    seen: dict[str, object] = {}
    monkeypatch.setattr(cbc_sdk.rest_api, "CBCloudAPI", lambda **kwargs: seen.update(kwargs))
    CarbonBlackCloudService(_tenant(ssl, url="https://cbc.example", token="t", org_key="o"))

    assert seen["ssl_verify"] is ssl


def test_carbon_black_refuses_an_unset_ssl_placeholder() -> None:
    from opentide.platforms.carbon_black.client import CarbonBlackCloudService

    with pytest.raises(
        ValueError, match=r"carbon_black_cloud tenant 'Primary' setup: ssl is unset"
    ):
        CarbonBlackCloudService(_tenant("$TENANT_SSL", url="u", token="t", org_key="o"))


@pytest.mark.parametrize("value", ["false", 0, None])
def test_tenant_tls_verify_refuses_anything_but_a_boolean(value: object) -> None:
    with pytest.raises(ValueError, match="ssl must be true or false"):
        tenant_tls_verify(value, platform="harfanglab", tenant="Primary")
