"""Sysdig tenant setup: url and api_token, nothing else (sysdig-1.0, Tenant setup)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from opentide.core.io import load_toml
from opentide.platforms.config import build_system_config

BUNDLED = Path(__file__).resolve().parents[2] / "src/opentide/data/configurations/platforms"


def _config(setup: dict[str, Any]) -> Any:
    raw = {
        "platform": {"enabled": True, "identifier": "sysdig"},
        "tenants": [{"name": "prod", "setup": setup}],
    }
    return build_system_config("sysdig", raw)


def test_the_bundled_file_is_off_and_has_no_tenant() -> None:
    raw = load_toml(BUNDLED / "sysdig.toml")
    assert raw["platform"] == {
        "enabled": False,
        "identifier": "sysdig",
        "name": "Sysdig Secure",
        "subschema": "Sysdig Secure",
        "description": "Custom Falco rules for Sysdig Secure runtime detection.",
        "flags": [],
    }
    assert "tenants" not in raw
    assert build_system_config("sysdig", raw).tenants is None


def test_an_api_tenant_resolves_its_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSDIG_TOKEN", "resolved")
    config = _config(
        {"url": "https://eu1.app.sysdig.com", "api_token": "${SYSDIG_TOKEN}", "policies": ["p"]}
    )
    (tenant,) = config.tenants
    assert tenant.setup.api_token == "resolved"
    assert tenant.setup.policies == ["p"]


@pytest.mark.parametrize("key", ["delivery", "rules_dir"])
def test_the_retired_file_delivery_keys_are_unknown(key: str) -> None:
    """Sysdig is configured over the API only: a rules-file tenant fails load."""
    with pytest.raises(ValueError, match=key):
        _config({"url": "https://x", "api_token": "$T", key: "file"})


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ({"api_token": "$T"}, "missing required key\\(s\\): url"),
        ({"url": "https://x"}, "missing required key\\(s\\): api_token"),
        ({}, "missing required key\\(s\\): url, api_token"),
        ({"url": "https://x", "api_token": "literal"}, "api_token must be an environment variable"),
    ],
)
def test_a_tenant_missing_its_keys_fails_by_name(setup: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _config(setup)
