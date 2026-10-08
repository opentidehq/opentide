"""Placeholder guards for live vendor clients."""

from __future__ import annotations

import pytest

from opentide.core.environment import reject_unsubstituted_placeholders


def test_reject_unsubstituted_placeholders_names_the_literals() -> None:
    with pytest.raises(ValueError, match=r"\$AZURE_TENANT_ID") as exc:
        reject_unsubstituted_placeholders(
            "$AZURE_TENANT_ID",
            "real-client",
            "$AZURE_CLIENT_SECRET",
            client="Azure",
        )
    message = str(exc.value)
    assert "Azure credentials are unset" in message
    assert "$AZURE_CLIENT_SECRET" in message
    assert "real-client" not in message


def test_reject_unsubstituted_placeholders_ignores_resolved_values() -> None:
    reject_unsubstituted_placeholders("tenant", "client", 8089, client="Splunk")


def test_connect_splunk_rejects_placeholders_before_the_sdk() -> None:
    from opentide.platforms.splunk.client import connect_splunk

    with pytest.raises(ValueError, match=r"\$SPLUNK_TOKEN"):
        connect_splunk(host="$SPLUNK_URL", port=8089, token="$SPLUNK_TOKEN", app="search")
