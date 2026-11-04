"""``setup_variables``: the $VAR names a tenant's setup references (#754)."""

from __future__ import annotations

from opentide.platforms.config import setup_variables


def test_names_each_reference_once_in_order_and_never_a_value() -> None:
    setup = {
        "url": "https://example.test",
        "api_key": "${ELASTIC_API_KEY}",
        "client_secret": "$CLIENT_SECRET",
        "nested": {"token": "$CLIENT_SECRET", "headers": ["$HEADER_TOKEN", "plain"]},
        "ssl": True,
        "port": 443,
        "lone": "$",
    }
    assert setup_variables(setup) == ["ELASTIC_API_KEY", "CLIENT_SECRET", "HEADER_TOKEN"]


def test_no_setup_names_nothing() -> None:
    assert setup_variables({}) == []
    assert setup_variables(None) == []
