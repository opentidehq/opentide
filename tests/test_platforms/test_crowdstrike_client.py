"""CrowdStrike client setup: API domains and the service's identity."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from opentide.platforms.crowdstrike import client
from opentide.platforms.crowdstrike.client import CrowdstrikeService


@pytest.mark.parametrize(
    ("domain", "base"),
    [
        ("US-1", "https://api.crowdstrike.com"),
        ("US-2", "https://api.us-2.crowdstrike.com"),
        ("EU-1", "https://api.eu-1.crowdstrike.com"),
        ("US-GOV-1", "https://api.laggar.gcw.crowdstrike.com"),
        ("US-GOV-2", "https://api.falcon.us-gov-2.crowdstrike.mil"),
    ],
)
def test_every_documented_api_domain_resolves(domain: str, base: str) -> None:
    """``US-GOV-1`` was matched as ``"US-GOV-1:"`` and refused as an invalid domain."""
    service = CrowdstrikeService.__new__(CrowdstrikeService)
    assert service._get_base_api(domain) == base


@pytest.mark.usefixtures("tide_corpus_repo")
def test_the_service_identifies_as_crowdstrike(monkeypatch: pytest.MonkeyPatch) -> None:
    """It took SentinelOne's platform identifier from the registry as its own."""

    def post(**_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(status_code=201, json=lambda: {"access_token": "token"})

    monkeypatch.setattr(client.requests, "post", post)
    tenant = SimpleNamespace(
        name="falcon-prod",
        setup=SimpleNamespace(ssl=True, api="US-GOV-1", client_id="id", client_secret="secret"),
    )
    service = CrowdstrikeService(tenant)

    assert service.DEPLOYER_IDENTIFIER == "crowdstrike"
    assert service.OAUTH_TOKEN_ENDPOINT == "https://api.laggar.gcw.crowdstrike.com/oauth2/token"
