"""``OPENTIDE_PROXY`` routes platform calls through a proxy, and ``NO_PROXY`` still applies.

Behind a corporate proxy a cloud tenant (Sentinel) needs the proxy and an
internal one (Splunk) must not use it: through the proxy, Splunk answered with
the proxy's HTML error page. Splitting the deploy job per platform is not
needed for that. The proxy comes from ``--proxy`` or ``OPENTIDE_PROXY``, and a
host listed in ``NO_PROXY`` is reached directly. The real Splunk validator and
client run here; the proxy is a socket that counts connections.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import clear_runtime_caches, materialise_corpus
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()

_ENVIRONMENT = ("CI", "GITHUB_ACTIONS", "TF_BUILD", "DEPLOYMENT_PLAN")
_PROXIES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "OPENTIDE_PROXY")


class _CountingProxy:
    """Accepts connections, counts them and hangs up without answering."""

    def __init__(self) -> None:
        self._server = socket.socket()
        self._server.bind(("127.0.0.1", 0))
        self._server.listen()
        self._server.settimeout(0.2)
        self.port = self._server.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._server.accept()
            except OSError:
                continue
            self.connections += 1
            client.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join()
        self._server.close()


@pytest.fixture
def proxy() -> Iterator[_CountingProxy]:
    server = _CountingProxy()
    yield server
    server.close()


@pytest.fixture
def closed_port() -> int:
    """A local port nothing listens on: the internal tenant, refusing connections."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, closed_port: int) -> Iterator[Path]:
    repo = materialise_corpus(tmp_path / "corpus")
    for name in _ENVIRONMENT + _PROXIES + tuple(name.lower() for name in _PROXIES):
        monkeypatch.delenv(name, raising=False)
    for name in ("TIDE_SPLUNK_SSL_ENABLED", "TIDE_SPLUNK_PLUGIN_ALLOW_HTTP_ERRORS"):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    config = repo / ".opentide/configurations/systems/splunk.toml"
    tenant = (
        '\n[[tenants]]\nname = "internal"\ndeployment = "ALWAYS"\n'
        f'[tenants.setup]\nssl = false\nurl = "127.0.0.1"\nport = {closed_port}\n'
        'app = "search"\ntoken = "token"\n'
    )
    config.write_text(config.read_text(encoding="utf-8") + tenant, encoding="utf-8")
    # ``urlopen`` caches one opener, with the proxies of its first call.
    monkeypatch.setattr(urllib.request, "_opener", None)
    clear_runtime_caches()
    yield repo
    clear_runtime_caches()
    # ``--proxy`` writes these into the process environment, which CliRunner
    # does not restore; the monkeypatch teardown then puts back the originals.
    for name in ("HTTP_PROXY", "HTTPS_PROXY"):
        os.environ.pop(name, None)


def _validate_splunk(env: dict[str, str]) -> tuple[int, dict[str, object]]:
    result = runner.invoke(
        app, ["--json", "validate", "query", "--platform", "splunk", "--live"], env=env
    )
    return result.exit_code, json.loads(result.stdout)


@pytest.mark.usefixtures("repo")
def test_opentide_proxy_routes_platform_calls_through_the_proxy(proxy: _CountingProxy) -> None:
    code, payload = _validate_splunk({"OPENTIDE_PROXY": f"http://127.0.0.1:{proxy.port}"})

    assert code == 1, payload
    assert proxy.connections > 0


@pytest.mark.usefixtures("repo")
def test_no_proxy_reaches_an_internal_tenant_directly(
    proxy: _CountingProxy, closed_port: int
) -> None:
    code, payload = _validate_splunk(
        {"OPENTIDE_PROXY": f"http://127.0.0.1:{proxy.port}", "NO_PROXY": "127.0.0.1"}
    )

    assert code == 1, payload
    assert proxy.connections == 0
    # The tenant itself refused the connection: it was tried directly.
    assert payload["host"] == f"127.0.0.1:{closed_port}"
    assert "refused" in str(payload["message"]).lower()
