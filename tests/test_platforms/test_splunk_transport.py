"""Splunk transport against a self-signed HTTPS stand-in (``tests.splunk_support``).

Every test goes through splunklib and opentide's request handler, so a
tenant's ``ssl`` setting is checked by a real TLS handshake rather than by a
mock, and the saved search arguments by a handler that refuses what Splunk
refuses.
"""

from __future__ import annotations

import os
import ssl
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import pytest
from tests.splunk_support import (
    CONF_ONLY_ARGUMENTS,
    SAVED_SEARCHES,
    SplunkStandIn,
    serve_splunk,
)

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.splunk.client import HTTP_ERROR_STATUS, connect_splunk

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
