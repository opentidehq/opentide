"""``setup_variables``: the $VAR names a tenant's setup references (#754)."""

from __future__ import annotations

import json

import pytest

from opentide.core.environment import DebugHelpers
from opentide.platforms.config import _load_tenants, setup_variables


def test_names_each_reference_once_in_order_and_never_a_value() -> None:
    setup = {
        "url": "https://example.test",
        "api_key": "${ELASTIC_API_KEY}",
        "client_secret": "$CLIENT_SECRET",
        "again": "$CLIENT_SECRET",
        "ssl": True,
        "port": 443,
        "lone": "$",
    }
    assert setup_variables(setup) == ["ELASTIC_API_KEY", "CLIENT_SECRET"]


def test_a_dollar_prefixed_literal_is_not_a_variable_name() -> None:
    # A secret that happens to start with `$` is a value: never printed.
    setup = {"azure_client_secret": "$uP3r-S3cret!pass", "workspace_id": "$WS"}
    names = setup_variables(setup)
    assert names == ["WS"]
    assert "uP3r" not in json.dumps(names)


def test_nested_values_are_not_references_since_the_resolver_skips_them() -> None:
    # fetch_config_envvar resolves top-level setup values only.
    assert setup_variables({"headers": ["$HEADER_TOKEN"], "nested": {"t": "$T"}}) == []


def test_a_braced_reference_names_the_variable_the_loader_resolves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROBE_WS", "abc")
    setup = {"workspace_id": "${PROBE_WS}", "workspace_name": "$PROBE_WS"}
    assert setup_variables(setup) == ["PROBE_WS"]
    assert DebugHelpers.fetch_config_envvar(dict(setup)) == {
        "workspace_id": "abc",
        "workspace_name": "abc",
    }
    tenants = _load_tenants(
        "sentinel",
        [
            {
                "name": "prod",
                "setup": {
                    "workspace_id": "${PROBE_WS}",
                    "workspace_name": "w",
                    "resource_group": "r",
                    "azure_subscription_id": "s",
                    "azure_tenant_id": "t",
                    "azure_client_id": "c",
                    "azure_client_secret": "x",
                },
            }
        ],
    )
    assert tenants[0].setup.workspace_id == "abc"


def test_a_dollar_literal_is_left_as_written_and_not_logged(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    resolved = DebugHelpers.fetch_config_envvar({"secret": "$uP3r-S3cret!pass"})
    assert resolved == {"secret": "$uP3r-S3cret!pass"}
    captured = capsys.readouterr()
    assert "uP3r" not in caplog.text + captured.out + captured.err


def test_no_setup_names_nothing() -> None:
    assert setup_variables({}) == []
    assert setup_variables(None) == []
