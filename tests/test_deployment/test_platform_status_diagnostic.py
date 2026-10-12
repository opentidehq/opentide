"""The deploy planner must name the object when a platform status is absent (#486).

``conf_data[system]["status"]`` raised a bare ``KeyError``, which the CLI
rendered as a FATAL panel whose entire content was ``'status'`` -- no file, no
UUID, no field path. The model now requires ``status``, so reaching the planner
without one means the object predates that rule or bypassed validation; either
way the error has to say which object.
"""

from __future__ import annotations

import pytest

from opentide.deployment.utils import _platform_status


def test_status_is_returned_when_present() -> None:
    block = {"status": "STAGING", "enabled": True}
    assert _platform_status(block, system="sentinel", rule="Some Rule", uuid="uuid-1") == "STAGING"


def test_status_is_stringified() -> None:
    """A YAML scalar that parses as non-string must not leak its type onward."""
    assert _platform_status({"status": 3}, system="splunk", rule="R", uuid="u") == "3"


@pytest.mark.parametrize(
    "block",
    [
        pytest.param({"enabled": True}, id="absent"),
        pytest.param({"status": None}, id="null"),
        pytest.param({"status": ""}, id="empty"),
        pytest.param("not-a-mapping", id="not-a-mapping"),
    ],
)
def test_missing_status_names_the_rule_the_uuid_and_the_platform(block: object) -> None:
    with pytest.raises(KeyError) as caught:
        _platform_status(block, system="sentinel", rule="Credential Dumping", uuid="abc-123")

    message = str(caught.value)
    # The three things the old one-word panel never told anyone.
    assert "Credential Dumping" in message
    assert "abc-123" in message
    assert "configurations.sentinel.status" in message
