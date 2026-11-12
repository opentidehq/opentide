"""Graylog tenant setup (graylog-1.0, Tenant setup)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from opentide.core.io import load_toml
from opentide.models.configuration.platforms import (
    PLATFORM_CONFIGURATION_MODELS,
    GraylogConfiguration,
)
from opentide.platforms.config import build_system_config

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

BUNDLED = Path(__file__).resolve().parents[2] / "src/opentide/data/configurations/platforms"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "graylog" / "tenant.toml"
STREAM = "65f0c0ffee0123456789abcd"


def _config(setup: dict[str, Any]) -> Any:
    raw = {"platform": {"enabled": True}, "tenants": [{"name": "gl", "setup": setup}]}
    return build_system_config("graylog", raw)


def _setup(**keys: Any) -> dict[str, Any]:
    return {"url": "https://graylog.example.com", "token": "$GRAYLOG_TOKEN", **keys}


def test_the_bundled_file_is_off_and_has_no_tenant() -> None:
    raw = load_toml(BUNDLED / "graylog.toml")
    assert raw["platform"]["enabled"] is False
    assert raw["platform"]["name"] == "Graylog"
    assert "tenants" not in raw
    assert build_system_config("graylog", raw).tenants is None


def test_the_specification_tenant_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAYLOG_TOKEN", "resolved")
    raw = tomllib.loads(FIXTURE.read_text(encoding="utf-8"))
    # The fixture's [platform] table carries identifier, subschema and flags, which
    # opentide's shared platform identity does not take on any platform.
    for key in ("identifier", "subschema", "flags"):
        del raw["platform"][key]
    (tenant,) = build_system_config("graylog", raw).tenants
    assert tenant.setup.token == "resolved"
    assert tenant.setup.allow_leading_wildcard is False
    assert tenant.setup.streams == ["sysmon"]
    assert tenant.setup.stream_ids["sysmon"] == STREAM
    assert tenant.setup.notification_ids == {"soc-slack": "65f0c0ffee0123456789abcf"}
    assert tenant.setup.tags == ["managed-by-opentide"]
    assert PLATFORM_CONFIGURATION_MODELS["graylog"] is GraylogConfiguration
    GraylogConfiguration.model_validate(raw)


def test_a_braced_reference_is_read_as_the_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAYLOG_TOKEN", "resolved")
    (tenant,) = _config(_setup(token="${GRAYLOG_TOKEN}", streams="sysmon")).tenants
    assert tenant.setup.token == "resolved"
    assert tenant.setup.streams == "sysmon"
    assert tenant.setup.ssl is True


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        (_setup(token="literal-token"), "token must be an environment variable reference"),
        ({"url": "https://graylog.example.com"}, "missing required key(s): token"),
        ({"token": "$GRAYLOG_TOKEN"}, "missing required key(s): url"),
        (_setup(index="x"), "unknown key(s): index"),
        (_setup(stream_ids={"sysmon": "1"}), "stream_ids.sysmon must be a Graylog id"),
        (
            _setup(notification_ids={"soc": STREAM.upper()}),
            "notification_ids.soc must be a Graylog id",
        ),
        (_setup(stream_ids=["x"]), "stream_ids must be a table"),
        (_setup(allow_leading_wildcard="yes"), "allow_leading_wildcard must be true or false"),
        (_setup(streams=["sysmon", ""]), "streams must be a string or a list"),
        (_setup(tags=3), "tags must be a string or a list"),
    ],
)
def test_a_bad_setup_fails_configuration_load(setup: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match="graylog tenant 'gl'") as caught:
        _config(setup)
    assert message in str(caught.value)


@pytest.mark.parametrize(
    "setup",
    [
        _setup(unknown=1),
        _setup(stream_ids={"sysmon": "xyz"}),
        {"url": "https://graylog.example.com"},
        _setup(streams=[""]),
    ],
)
def test_the_configuration_model_refuses_the_same(setup: dict[str, Any]) -> None:
    raw = {"platform": {"enabled": True}, "tenants": [{"name": "gl", "setup": setup}]}
    with pytest.raises(ValidationError):
        GraylogConfiguration.model_validate(raw)
