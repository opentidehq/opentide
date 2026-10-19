"""A tenant the live check cannot reach is a failed result, not a traceback (#565 review).

``validate query --live`` against a closed port escaped as an uncaught ``URLError``
(Splunk) or ``requests`` traceback, with nothing on stdout. The real validators
and vendor clients run here; only the tenant address is unreachable.
"""

from __future__ import annotations

import json
import re
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import clear_runtime_caches, materialise_corpus
from typer.testing import CliRunner
from urllib3.util import Retry

from opentide.cli import app

runner = CliRunner()

_ENVIRONMENT = ("CI", "GITHUB_ACTIONS", "TF_BUILD", "DEPLOYMENT_PLAN")
_PROXIES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


@pytest.fixture
def closed_port() -> int:
    """A local port nothing listens on: connecting to it is refused."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    repo = materialise_corpus(tmp_path / "corpus")
    for name in _ENVIRONMENT + _PROXIES + tuple(name.lower() for name in _PROXIES):
        monkeypatch.delenv(name, raising=False)
    # The validators flag through the environment; restore it afterwards.
    for name in ("TIDE_SPLUNK_SSL_ENABLED", "TIDE_SPLUNK_PLUGIN_ALLOW_HTTP_ERRORS"):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    clear_runtime_caches()
    yield repo
    clear_runtime_caches()


def _config(repo: Path, platform: str) -> Path:
    return repo / ".opentide/configurations/systems" / f"{platform}.toml"


def _add_tenant(repo: Path, platform: str, setup: str) -> None:
    config = _config(repo, platform)
    tenant = (
        '\n[[tenants]]\nname = "unreachable"\ndeployment = "ALWAYS"\n'
        f"[tenants.setup]\nssl = false\n{setup}"
    )
    config.write_text(config.read_text(encoding="utf-8") + tenant, encoding="utf-8")


def _validate(platform: str) -> tuple[int, dict[str, object]]:
    result = runner.invoke(app, ["--json", "validate", "query", "--platform", platform, "--live"])
    assert result.stdout, f"no result on stdout: {result.exception!r}"
    assert "Traceback" not in result.stderr
    return result.exit_code, json.loads(result.stdout)


def _assert_unreachable(platform: str, tenant: str, host: str) -> None:
    exit_code, payload = _validate(platform)
    assert exit_code == 1
    assert payload["ok"] is False
    assert payload["status"] == "failed"
    assert payload["mode"] == "live"
    assert payload["platform"] == platform
    assert payload["tenant"] == tenant
    assert payload["host"] == host
    message = str(payload["message"])
    assert message.startswith(f"Cannot reach {platform} tenant '{tenant}' at {host}: ")
    assert "refused" in message.lower()
    assert f"{platform}.toml" in str(payload["advice"])


def test_splunk(repo: Path, closed_port: int) -> None:
    """The reported case: ``urllib`` raised ``URLError`` through splunklib."""
    _add_tenant(
        repo,
        "splunk",
        f'url = "127.0.0.1"\nport = {closed_port}\napp = "search"\ntoken = "token"\n',
    )
    _assert_unreachable("splunk", "unreachable", f"127.0.0.1:{closed_port}")


def test_sentinel_one(repo: Path, closed_port: int) -> None:
    url = f"https://127.0.0.1:{closed_port}"
    _add_tenant(repo, "sentinel_one", f'url = "{url}"\naccount_id = 1\napi_token = "token"\n')
    _assert_unreachable("sentinel_one", "unreachable", url)


def test_carbon_black_cloud(repo: Path, closed_port: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """The SDK wraps the ``requests`` error in its own ``ConnectionError``."""
    monkeypatch.setattr("cbc_sdk.connection.MAX_RETRIES", 0)  # its backoff takes 15s
    url = f"https://127.0.0.1:{closed_port}"
    _add_tenant(repo, "carbon_black_cloud", f'url = "{url}"\norg_key = "ORG"\ntoken = "token"\n')
    _assert_unreachable("carbon_black_cloud", "unreachable", url)


def test_elastic(repo: Path, closed_port: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """The client retries the refused connection, then the tenant is reported."""
    monkeypatch.setattr(
        "opentide.platforms.elastic.client.Retry",
        lambda **kwargs: Retry(**{**kwargs, "backoff_factor": 0}),
    )
    monkeypatch.setenv("ELASTIC_API_KEY", "key")
    origin = f"http://127.0.0.1:{closed_port}"
    config = _config(repo, "elastic")
    text = re.sub(
        r'(?m)^(url|elasticsearch_url) = ".*"$',
        rf'\1 = "{origin}/proxied"',
        config.read_text("utf-8"),
    )
    config.write_text(text, encoding="utf-8")
    # The corpus tenant; the host is the origin the request failed on, without its path.
    _assert_unreachable("elastic", "staging", origin)


def test_defender_for_endpoint_behind_an_unreachable_proxy(
    repo: Path, closed_port: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its endpoints are Microsoft's, so the network is cut at the proxy instead."""
    for name in ("HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{closed_port}")
    _add_tenant(
        repo,
        "defender_for_endpoint",
        'tenant_id = "tenant"\nclient_id = "client"\nclient_secret = "secret"\n',
    )
    _assert_unreachable("defender_for_endpoint", "unreachable", "https://login.microsoftonline.com")


def test_defender_for_endpoint_hunting_query_behind_an_unreachable_proxy(
    repo: Path, closed_port: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused hunting query is the tenant's result, not a silent per-rule failure."""
    monkeypatch.setattr(
        "opentide.platforms.defender_for_endpoint.client.DefenderForEndpointService._connect_to_tenant",
        lambda *args: "token",
    )
    for name in ("HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{closed_port}")
    _add_tenant(
        repo,
        "defender_for_endpoint",
        'tenant_id = "tenant"\nclient_id = "client"\nclient_secret = "secret"\n',
    )
    _assert_unreachable("defender_for_endpoint", "unreachable", "https://graph.microsoft.com")
