"""OAuth clients must not write bearer tokens or client secrets into logs.

``opentide --json`` (the documented CI mode) and ``--debug`` raise the log level
to INFO or DEBUG, and GitHub Actions keeps stderr. Logging ``response.json()``
from a client-credentials grant publishes the access token to those readers.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from structlog.testing import capture_logs

from opentide.core.errors import Errors
from opentide.platforms.crowdstrike.client import CrowdstrikeService
from opentide.platforms.defender_for_endpoint.client import DefenderForEndpointService


class _Response:
    def __init__(self, status_code: int, payload: dict[str, object]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, object]:
        return self._payload


def _service(cls: type, name: str) -> object:
    service = cls.__new__(cls)
    service.tenant_config = SimpleNamespace(name=name, setup=SimpleNamespace(ssl=True))
    service.OAUTH_TOKEN_ENDPOINT = "https://login.example/oauth2/token"
    return service


def _rendered(logs: list[dict[str, object]]) -> str:
    return " ".join(str(value) for entry in logs for value in entry.values())


def test_crowdstrike_success_log_omits_access_token(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "cs-live-access-token"
    secret = "cs-client-secret-value"

    def post(**_kwargs: object) -> _Response:
        return _Response(201, {"access_token": token, "token_type": "bearer"})

    monkeypatch.setattr("opentide.platforms.crowdstrike.client.requests.post", post)
    service = _service(CrowdstrikeService, "falcon-prod")

    with capture_logs() as logs:
        assert service._get_access_token("client-id", secret) == token

    rendered = _rendered(logs)
    assert token not in rendered
    assert secret not in rendered
    assert logs


def test_crowdstrike_failure_log_omits_client_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "cs-client-secret-value"

    def post(**_kwargs: object) -> _Response:
        return _Response(401, {"errors": [{"message": f"rejected {secret}"}]})

    monkeypatch.setattr("opentide.platforms.crowdstrike.client.requests.post", post)
    service = _service(CrowdstrikeService, "falcon-prod")

    with capture_logs() as logs, pytest.raises(Errors.TenantConnectionError):
        service._get_access_token("client-id", secret)

    rendered = _rendered(logs)
    assert secret not in rendered
    assert secret[:10] not in rendered
    assert "401" in rendered


def test_defender_success_log_omits_access_token(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "graph-live-access-token"
    secret = "graph-client-secret-value"

    def post(**_kwargs: object) -> _Response:
        return _Response(200, {"access_token": token, "token_type": "Bearer"})

    monkeypatch.setattr(
        "opentide.platforms.defender_for_endpoint.client.requests.post",
        post,
    )
    service = _service(DefenderForEndpointService, "mde-prod")

    with capture_logs() as logs:
        assert service._connect_to_tenant("client-id", "tenant-id", secret) == token

    rendered = _rendered(logs)
    assert token not in rendered
    assert secret not in rendered


def test_defender_failure_log_omits_client_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "graph-client-secret-value"

    def post(**_kwargs: object) -> _Response:
        return _Response(400, {"error": "invalid_client", "error_description": secret})

    monkeypatch.setattr(
        "opentide.platforms.defender_for_endpoint.client.requests.post",
        post,
    )
    service = _service(DefenderForEndpointService, "mde-prod")

    with capture_logs() as logs, pytest.raises(Errors.TenantConnectionError):
        service._connect_to_tenant("client-id", "tenant-id", secret)

    rendered = _rendered(logs)
    assert secret not in rendered
    assert secret[:10] not in rendered
    assert "400" in rendered
