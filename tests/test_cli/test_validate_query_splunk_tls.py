"""``validate query --live`` honours each Splunk tenant's ``ssl`` setting.

0.17.0 passed the tenant's ``ssl`` through ``TIDE_SPLUNK_SSL_ENABLED`` and
tested the string, so ``ssl = false`` (the string ``"False"``) still verified
the certificate: against a self-signed Splunk every live check failed. The
tenant here is a local HTTPS stand-in with a self-signed certificate.
"""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from tests.corpus_support import clear_runtime_caches, materialise_corpus
from tests.splunk_support import (
    InterceptingProxy,
    SplunkStandIn,
    serve_intercepting_proxy,
    serve_splunk,
)
from typer.testing import CliRunner

from opentide.cli import app

pytest.importorskip("cryptography")

runner = CliRunner()

_ENVIRONMENT = ("CI", "GITHUB_ACTIONS", "TF_BUILD", "DEPLOYMENT_PLAN")
_PROXIES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "OPENTIDE_PROXY")


@pytest.fixture
def splunk(tmp_path: Path) -> Iterator[SplunkStandIn]:
    with serve_splunk(tmp_path) as stand_in:
        yield stand_in


@pytest.fixture
def tenant_ssl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, splunk: SplunkStandIn
) -> Iterator[Callable[[str], None]]:
    """Write the corpus's Splunk tenant pointing at the stand-in, with ``ssl = <value>``."""
    repo = materialise_corpus(tmp_path / "corpus")
    for name in _ENVIRONMENT + _PROXIES + tuple(name.lower() for name in _PROXIES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    config = repo / ".opentide/configurations/systems/splunk.toml"
    original = config.read_text(encoding="utf-8")

    def _write(value: str) -> None:
        tenant = (
            '\n[[tenants]]\nname = "self-signed"\n'
            f'[tenants.setup]\nssl = {value}\nurl = "localhost"\nport = {splunk.port}\n'
            'app = "search"\ntoken = "token"\n'
        )
        config.write_text(original + tenant, encoding="utf-8")
        clear_runtime_caches()

    yield _write
    clear_runtime_caches()


def _validate_splunk() -> tuple[int, dict[str, object]]:
    result = runner.invoke(app, ["--json", "validate", "query", "--platform", "splunk", "--live"])
    return result.exit_code, json.loads(result.stdout)


def _parsed(splunk: SplunkStandIn) -> int:
    return sum(path.endswith("parser") for _, path, _ in splunk.requests)


@pytest.mark.parametrize("value", ["false", '"false"'])
def test_ssl_false_validates_against_a_self_signed_tenant(
    tenant_ssl: Callable[[str], None], splunk: SplunkStandIn, value: str
) -> None:
    tenant_ssl(value)
    code, payload = _validate_splunk()

    assert code == 0, payload
    assert _parsed(splunk) > 0


def test_ssl_false_from_an_environment_variable(
    tenant_ssl: Callable[[str], None], splunk: SplunkStandIn, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SPLUNK_SSL", "false")
    tenant_ssl('"$SPLUNK_SSL"')
    code, payload = _validate_splunk()

    assert code == 0, payload
    assert _parsed(splunk) > 0


def test_ssl_true_refuses_a_self_signed_tenant(
    tenant_ssl: Callable[[str], None], splunk: SplunkStandIn
) -> None:
    tenant_ssl("true")
    code, payload = _validate_splunk()

    assert code == 1, payload
    assert "certificate" in json.dumps(payload).lower()
    assert _parsed(splunk) == 0


def test_an_ssl_that_is_not_a_boolean_names_the_tenant(
    tenant_ssl: Callable[[str], None],
) -> None:
    tenant_ssl('"sometimes"')
    result = runner.invoke(app, ["--json", "validate", "query", "--platform", "splunk", "--live"])

    assert result.exit_code != 0
    assert "splunk tenant 'self-signed' setup: ssl must be true or false" in result.output


@pytest.fixture
def intercepting_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[InterceptingProxy]:
    monkeypatch.setattr(urllib.request, "_opener", None)
    (tmp_path / "proxy").mkdir()
    with serve_intercepting_proxy(tmp_path / "proxy") as proxy:
        yield proxy
    # ``--proxy`` / OPENTIDE_PROXY write these into the process environment.
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ.pop(name, None)


def test_a_proxy_page_names_the_proxy_and_no_proxy(
    tenant_ssl: Callable[[str], None],
    splunk: SplunkStandIn,
    intercepting_proxy: InterceptingProxy,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 0.17.1 report: an ssl = false tenant behind OPENTIDE_PROXY failed with a ParseError."""
    tenant_ssl("false")
    monkeypatch.setenv("OPENTIDE_PROXY", f"http://127.0.0.1:{intercepting_proxy.port}")
    code, payload = _validate_splunk()

    text = json.dumps(payload)
    assert code == 1, payload
    assert "ParseError" not in text
    assert "answered with an HTML page" in text
    assert f"through the proxy http://127.0.0.1:{intercepting_proxy.port}" in text
    assert "NO_PROXY=localhost" in text
    assert _parsed(splunk) == 0


def test_no_proxy_takes_the_tenant_off_the_proxy(
    tenant_ssl: Callable[[str], None],
    splunk: SplunkStandIn,
    intercepting_proxy: InterceptingProxy,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_ssl("false")
    monkeypatch.setenv("OPENTIDE_PROXY", f"http://127.0.0.1:{intercepting_proxy.port}")
    monkeypatch.setenv("NO_PROXY", "localhost")
    monkeypatch.setenv("no_proxy", "localhost")
    code, payload = _validate_splunk()

    assert code == 0, payload
    assert intercepting_proxy.tunnels == 0
    assert _parsed(splunk) > 0
