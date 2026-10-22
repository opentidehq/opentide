"""Splunk transport against a self-signed HTTPS stand-in (``tests.splunk_support``).

Every test goes through splunklib and opentide's request handler, so a
tenant's ``ssl`` setting is checked by a real TLS handshake rather than by a
mock, and the saved search arguments by a handler that refuses what Splunk
refuses.
"""

from __future__ import annotations

import os
import ssl
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import pytest
from tests.splunk_support import (
    CONF_ONLY_ARGUMENTS,
    SAVED_SEARCHES,
    InterceptingProxy,
    SplunkStandIn,
    serve_block_page,
    serve_intercepting_proxy,
    serve_splunk,
)

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.splunk.client import (
    HTTP_ERROR_STATUS,
    SplunkAnsweredHtmlError,
    connect_splunk,
    splunk_route,
)

pytest.importorskip("cryptography")


@pytest.fixture
def splunk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[SplunkStandIn]:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    with serve_splunk(tmp_path) as stand_in:
        yield stand_in


def _connect(splunk: SplunkStandIn, *, ssl_enabled: bool, allow_http_errors: bool = False):
    return connect_splunk(
        host="localhost",
        port=splunk.port,
        token="token",
        app="search",
        allow_http_errors=allow_http_errors,
        ssl_enabled=ssl_enabled,
    )


# --- ssl comes from the tenant -------------------------------------------------


def test_ssl_false_reaches_a_self_signed_tenant(splunk: SplunkStandIn) -> None:
    service = _connect(splunk, ssl_enabled=False)
    with pytest.raises(KeyError):
        service.saved_searches["absent"]
    assert splunk.requests, "the request never reached the tenant"


def test_ssl_true_refuses_a_self_signed_tenant(splunk: SplunkStandIn) -> None:
    service = _connect(splunk, ssl_enabled=True)
    with pytest.raises(URLError) as exc:
        service.saved_searches["absent"]
    assert isinstance(exc.value.reason, ssl.SSLCertVerificationError)
    assert splunk.requests == []


@pytest.mark.parametrize("stale", ["True", "False", ""])
def test_retired_environment_variable_is_ignored(
    splunk: SplunkStandIn, monkeypatch: pytest.MonkeyPatch, stale: str
) -> None:
    """0.17.0 read TIDE_SPLUNK_SSL_ENABLED, where the string "False" is truthy."""
    monkeypatch.setenv("TIDE_SPLUNK_SSL_ENABLED", stale)
    with pytest.raises(KeyError):
        _connect(splunk, ssl_enabled=False).saved_searches["absent"]
    with pytest.raises(URLError):
        _connect(splunk, ssl_enabled=True).saved_searches["absent"]


def test_each_connection_keeps_its_own_tenant_ssl(splunk: SplunkStandIn) -> None:
    """Two tenants in one process: connecting the second leaves the first alone."""
    lenient = _connect(splunk, ssl_enabled=False)
    strict = _connect(splunk, ssl_enabled=True)
    with pytest.raises(KeyError):
        lenient.saved_searches["absent"]
    with pytest.raises(URLError):
        strict.saved_searches["absent"]
    with pytest.raises(KeyError):
        lenient.saved_searches["absent"]


def test_connect_leaves_the_process_environment_alone(
    splunk: SplunkStandIn, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("TIDE_SPLUNK_SSL_ENABLED", "TIDE_SPLUNK_PLUGIN_ALLOW_HTTP_ERRORS"):
        monkeypatch.delenv(name, raising=False)
    before = dict(os.environ)
    _connect(splunk, ssl_enabled=False, allow_http_errors=True)
    assert dict(os.environ) == before


@pytest.mark.parametrize("value", ["false", "False", "True", 0, 1, None])
def test_connect_refuses_an_ssl_that_is_not_a_boolean(value: object) -> None:
    with pytest.raises(ValueError, match="ssl must be true or false"):
        connect_splunk(
            host="localhost",
            port=8089,
            token="token",
            app="search",
            ssl_enabled=value,  # type: ignore[arg-type]
        )


def test_connect_refuses_an_unset_ssl_placeholder() -> None:
    with pytest.raises(ValueError, match=r"\$SPLUNK_SSL"):
        connect_splunk(
            host="localhost",
            port=8089,
            token="token",
            app="search",
            ssl_enabled="$SPLUNK_SSL",  # type: ignore[arg-type]
        )


# --- HTTP errors stay per connection -------------------------------------------


def test_http_errors_are_reported_only_to_the_connection_that_asked(splunk: SplunkStandIn) -> None:
    validating = _connect(splunk, ssl_enabled=False, allow_http_errors=True)
    response = validating.parse("| makeresults |badcommand", output_mode="json")
    assert response["status"] == HTTP_ERROR_STATUS

    deploying = _connect(splunk, ssl_enabled=False)
    from splunklib.binding import HTTPError

    with pytest.raises(HTTPError):
        deploying.parse("| makeresults |badcommand", output_mode="json")


def test_query_validator_reports_an_invalid_query(
    splunk: SplunkStandIn, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.platforms.splunk.validator import SplunkQueryValidator

    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    validator = SplunkQueryValidator.__new__(SplunkQueryValidator)
    service = _connect(splunk, ssl_enabled=False, allow_http_errors=True)

    validator._validate_spl_query("| makeresults", "good", "uuid-1", service)
    assert "VALIDATION_ERROR_RAISED" not in os.environ

    validator._validate_spl_query("| makeresults |badcommand", "bad", "uuid-2", service)
    assert os.environ.get("VALIDATION_ERROR_RAISED") == "True"


def test_query_validator_assumes_valid_on_a_network_error_redirect(
    splunk: SplunkStandIn, monkeypatch: pytest.MonkeyPatch
) -> None:
    """urllib raises on a 307 answering a POST; it is a validation response, not a failure."""
    from opentide.platforms.splunk.validator import SplunkQueryValidator

    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.delenv("VALIDATION_WARNING_RAISED", raising=False)
    validator = SplunkQueryValidator.__new__(SplunkQueryValidator)
    service = _connect(splunk, ssl_enabled=False, allow_http_errors=True)

    validator._validate_spl_query("| makeresults |unreachable", "slow", "uuid-3", service)
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "True"
    assert "VALIDATION_ERROR_RAISED" not in os.environ


def test_query_validator_reads_a_redirected_refusal_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A redirect that is not a network error is still a refusal, reported from its body.

    The body is a stream; reading it once for the network-error check left
    ``json.loads`` an empty one, and the check crashed instead of reporting.
    """
    from opentide.platforms.splunk.validator import SplunkQueryValidator

    class Body:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self) -> bytes:
            data, self._data = self._data, b""
            return data

    class Service:
        def parse(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "status": HTTP_ERROR_STATUS,
                "reason": "Temporary Redirect",
                "body": Body(b'{"messages": [{"type": "FATAL", "text": "Unknown command"}]}'),
            }

    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    validator = SplunkQueryValidator.__new__(SplunkQueryValidator)

    validator._validate_spl_query("| makeresults |badcommand", "bad", "uuid-4", Service())  # type: ignore[arg-type]
    assert os.environ.get("VALIDATION_ERROR_RAISED") == "True"


# --- a proxy's HTML page is named, not parsed as XML ---------------------------

_PROXY_VARIABLES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
)


@pytest.fixture
def proxy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[InterceptingProxy]:
    """A TLS-inspecting proxy in HTTPS_PROXY that answers every tunnel with a block page."""
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    # ``urlopen`` caches one opener, with the proxies of its first call.
    monkeypatch.setattr(urllib.request, "_opener", None)
    (tmp_path / "proxy").mkdir()
    with serve_intercepting_proxy(tmp_path / "proxy") as server:
        for name in ("HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{server.port}")
        yield server


def test_a_proxy_page_is_reported_with_the_proxy_and_no_proxy(
    splunk: SplunkStandIn, proxy: InterceptingProxy
) -> None:
    """0.17.0/0.17.1 failed here with ``ParseError: mismatched tag``, read as a TLS fault."""
    service = _connect(splunk, ssl_enabled=False)
    with pytest.raises(SplunkAnsweredHtmlError) as exc:
        service.saved_searches.create("Rule", search="index=main")

    message = str(exc.value)
    assert f"through the proxy http://127.0.0.1:{proxy.port}" in message
    assert "NO_PROXY=localhost" in message
    assert "'Access denied by policy'" in message
    assert isinstance(exc.value, ConnectionError)
    assert proxy.tunnels == 1
    assert splunk.requests == []


def test_no_proxy_reaches_an_internal_tenant_directly(
    splunk: SplunkStandIn, proxy: InterceptingProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "localhost")
    service = _connect(splunk, ssl_enabled=False)
    service.saved_searches.create("Rule", search="index=main")

    assert proxy.tunnels == 0
    assert "Rule" in splunk.saved_searches


def test_the_proxy_page_hides_proxy_credentials(
    splunk: SplunkStandIn, proxy: InterceptingProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(name, f"http://svc-user:s3cret@127.0.0.1:{proxy.port}")
    with pytest.raises(SplunkAnsweredHtmlError) as exc:
        _connect(splunk, ssl_enabled=False).saved_searches.create("Rule", search="index=main")

    assert "s3cret" not in str(exc.value)
    assert "svc-user" not in str(exc.value)
    assert f"http://127.0.0.1:{proxy.port}" in str(exc.value)


def test_an_html_answer_without_a_proxy_points_at_the_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Splunk Web on port 8000 answers HTML; the REST API is on the management port."""
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    with serve_block_page(tmp_path) as port:
        service = connect_splunk(
            host="localhost", port=port, token="token", app="search", ssl_enabled=False
        )
        with pytest.raises(SplunkAnsweredHtmlError, match="management port"):
            service.saved_searches["Rule"]


@pytest.mark.parametrize(
    ("content_type", "body", "html"),
    [
        ("text/html; charset=utf-8", b"anything", True),
        ("TEXT/HTML", b"", True),
        ("", b"  <!DOCTYPE html><html>", True),
        ("", b"<html><body>", True),
        ("text/xml; charset=UTF-8", b"<html>an event that is HTML</html>", False),
        ("application/json", b"<html>", False),
        ("text/plain", b"<!doctype html>", False),
        ("", b'<?xml version="1.0"?><feed/>', False),
    ],
)
def test_only_an_html_page_is_refused(content_type: str, body: bytes, html: bool) -> None:
    """A body Splunk labels XML, JSON or text is trusted, whatever it starts with."""
    from opentide.platforms.splunk.client import _looks_like_html

    headers = {"Content-Type": content_type} if content_type else {}
    assert _looks_like_html(headers, body) is html


def test_splunk_route_follows_no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    assert splunk_route("https://splunk.internal:8089/") is None

    monkeypatch.setenv("https_proxy", "http://user:pass@proxy.corp:3128")
    assert splunk_route("https://splunk.internal:8089/") == "http://proxy.corp:3128"

    monkeypatch.setenv("no_proxy", ".internal")
    assert splunk_route("https://splunk.internal:8089/") is None
    assert splunk_route("https://splunk.cloud.example:8089/") == "http://proxy.corp:3128"


def test_connect_logs_the_route(
    splunk: SplunkStandIn, proxy: InterceptingProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ``capture_logs`` misses a logger cached on first use by an earlier test.
    from structlog.testing import CapturingLogger

    from opentide.platforms.splunk import client as splunk_client

    captured = CapturingLogger()
    monkeypatch.setattr(splunk_client, "logger", captured)
    _connect(splunk, ssl_enabled=False)

    (route,) = [call for call in captured.calls if call.args == ("splunk_tenant_route",)]
    assert route.kwargs["via"] == f"http://127.0.0.1:{proxy.port}"


# --- trigger arguments match the REST endpoint ---------------------------------


@pytest.fixture
def trigger_rule(metadata: dict):
    return load_rule_from_dict(
        {
            "name": "Trigger Rule",
            "metadata": metadata,
            "description": "Detect suspicious activity",
            "response": {"alert_severity": "High"},
            "configurations": {
                "splunk": {
                    "schema": "splunk::3.0",
                    "status": "STAGING",
                    "query": "index=main | stats count by host",
                    "scheduling": {"schedule": {"frequency": "1h"}},
                    "trigger": {
                        "condition": "number of events",
                        "comparator": "greater than",
                        "threshold": 0,
                    },
                }
            },
        }
    )


def _tenant() -> ConfigurationModels.Systems.Splunk.Tenant:
    return ConfigurationModels.Systems.Splunk.Tenant(
        name="Self-signed",
        description="On-premises Splunk with a self-signed certificate",
        setup=ConfigurationModels.Systems.Splunk.Tenant.Setup(
            ssl=False, url="localhost", port=8089, app="search", token="token"
        ),
    )


def _deployer():
    from opentide.platforms.splunk.deployer import SplunkDeploy

    deployer = SplunkDeploy.__new__(SplunkDeploy)
    deployer.TIMERANGE_MODE = "current"
    deployer.SKEWING_VALUE = 0
    deployer.OFFSET = 0
    deployer.ALERT_SEVERITY_MAPPING = {"High": 5}
    deployer.CORRELATION_SEARCHES = False
    deployer.SPLUNK_ACTIONS = []
    deployer.SPLUNK_DEFAULT_ACTIONS = []
    deployer.DEFAULT_CONFIG = {}
    deployer.STATUS_MODIFIERS = []
    deployer.DEBUG_STEP = False
    return deployer


def test_the_stand_in_refuses_savedsearches_conf_spellings(splunk: SplunkStandIn) -> None:
    """The stand-in rejects what Splunk rejects, so the next test means something."""
    from splunklib.binding import HTTPError

    service = _connect(splunk, ssl_enabled=False)
    search = service.saved_searches.create("Legacy", search="index=main")
    with pytest.raises(HTTPError, match="is not supported by this handler"):
        search.update(counttype="number of events", relation="greater than", quantity=0)


@patch("opentide.platforms.splunk.deployer.techniques_resolver", return_value=[])
def test_trigger_deploys_with_the_rest_argument_names(
    _techniques: object, splunk: SplunkStandIn, trigger_rule
) -> None:
    service = _connect(splunk, ssl_enabled=False)
    assert _deployer().deploy_mdr(data=trigger_rule, service=service, tenant_config=_tenant())

    posted = splunk.posted("Trigger Rule")
    assert posted["alert_type"] == "number of events"
    assert posted["alert_comparator"] == "greater than"
    assert posted["alert_threshold"] == "0"
    assert not CONF_ONLY_ARGUMENTS & set(posted)
    assert splunk.saved_searches["Trigger Rule"]["alert_threshold"] == "0"


@patch("opentide.platforms.splunk.deployer.techniques_resolver", return_value=[])
def test_redeploy_updates_the_existing_saved_search(
    _techniques: object, splunk: SplunkStandIn, trigger_rule
) -> None:
    service = _connect(splunk, ssl_enabled=False)
    deployer = _deployer()
    deployer.deploy_mdr(data=trigger_rule, service=service, tenant_config=_tenant())
    deployer.deploy_mdr(data=trigger_rule, service=service, tenant_config=_tenant())
    creates = [r for r in splunk.requests if r[0] == "POST" and r[1] == SAVED_SEARCHES]
    assert len(creates) == 1
    assert splunk.saved_searches["Trigger Rule"]["alert_type"] == "number of events"


# --- retiring a rule removes its saved search ----------------------------------


def test_delete_reaches_splunk_as_a_delete(splunk: SplunkStandIn) -> None:
    """The handler named no method, so urllib sent every DELETE as a GET.

    Splunk answered the GET with the saved search, splunklib reported success
    and the retired rule kept running.
    """
    splunk.saved_searches["Retired Rule"] = {"search": "index=main"}
    service = _connect(splunk, ssl_enabled=False)
    service.saved_searches.delete("Retired Rule")

    assert [method for method, _path, _args in splunk.requests] == ["DELETE"]
    assert "Retired Rule" not in splunk.saved_searches


@pytest.fixture
def retiring(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every rule status carries the DELETION strategy."""
    from opentide.models.deployment_enums import StatusStrategy

    monkeypatch.setattr(
        "opentide.platforms.splunk.deployer.check_status", lambda _status: StatusStrategy.DELETION
    )


def _retire(service: object, name: str) -> bool | None:
    return _deployer()._apply_saved_search(
        service=service,
        name=name,
        status="REMOVED",
        query="index=main",
        mdr_config={},
        actions_config={},
    )


@pytest.mark.usefixtures("retiring")
def test_a_retired_rule_deletes_its_saved_search(splunk: SplunkStandIn) -> None:
    splunk.saved_searches["Retired Rule"] = {"search": "index=main"}
    _retire(_connect(splunk, ssl_enabled=False), "Retired Rule")

    assert "Retired Rule" not in splunk.saved_searches
    assert [method for method, _path, _args in splunk.requests] == ["GET", "DELETE"]


@pytest.mark.usefixtures("retiring")
def test_retiring_an_absent_saved_search_succeeds(splunk: SplunkStandIn) -> None:
    assert _retire(_connect(splunk, ssl_enabled=False), "Never Deployed") is None
    assert [method for method, _path, _args in splunk.requests] == ["GET"]


@pytest.mark.usefixtures("retiring")
def test_retiring_on_an_unreachable_tenant_fails(splunk: SplunkStandIn) -> None:
    """Any failure to look the saved search up used to read as "already absent".

    A TLS failure, a refused token or a 5xx left the saved search running
    while the run reported success.
    """
    splunk.saved_searches["Retired Rule"] = {"search": "index=main"}
    with pytest.raises(URLError):
        _retire(_connect(splunk, ssl_enabled=True), "Retired Rule")

    assert "Retired Rule" in splunk.saved_searches
