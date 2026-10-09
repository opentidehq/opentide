"""Placeholder guards for live vendor clients."""

from __future__ import annotations

import pytest
from structlog.testing import capture_logs

from opentide.core import environment
from opentide.core.environment import reject_unsubstituted_placeholders


def test_missing_envvar_is_logged_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTIDE_TEST_MISSING", raising=False)
    monkeypatch.delenv("OPENTIDE_TEST_ALSO_MISSING", raising=False)
    monkeypatch.setattr(environment.DebugHelpers, "is_debug", lambda: False)
    environment._reported_missing_envvars.clear()
    payload = {"token": "$OPENTIDE_TEST_MISSING", "secret": "$OPENTIDE_TEST_ALSO_MISSING"}
    with capture_logs() as logs:
        for _ in range(5):
            environment.DebugHelpers.fetch_config_envvar(dict(payload))
    missing = [entry for entry in logs if entry["event"] == "environment_variable_missing"]
    assert len(missing) == 1
    assert "$OPENTIDE_TEST_MISSING" in missing[0]["detail"]
    assert "$OPENTIDE_TEST_ALSO_MISSING" in missing[0]["detail"]
    assert not any(entry["event"] == "environment_variables_missing_summary" for entry in logs)


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
