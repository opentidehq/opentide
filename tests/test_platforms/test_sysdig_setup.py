"""Sysdig tenant setup: the keys each delivery needs (sysdig-1.0, Tenant setup)."""

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
        "description": "Falco rules for Sysdig Secure runtime detection, or as Falco rules files.",
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
    assert tenant.setup.delivery == "api"
    assert tenant.setup.api_token == "resolved"
    assert tenant.setup.policies == ["p"]


def test_a_file_tenant_needs_only_rules_dir() -> None:
    (tenant,) = _config({"delivery": "file", "rules_dir": "deploy/falco"}).tenants
    assert (tenant.setup.delivery, tenant.setup.rules_dir) == ("file", "deploy/falco")


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ({"api_token": "$T"}, "delivery api needs url"),
        ({"url": "https://x"}, "delivery api needs api_token"),
        ({"url": "https://x", "api_token": "literal"}, "api_token must be an environment variable"),
        ({"delivery": "file"}, "delivery file needs rules_dir"),
        ({"delivery": "ftp", "rules_dir": "x"}, "delivery must be api or file"),
    ],
)
def test_a_tenant_missing_its_delivery_keys_fails_by_name(
    setup: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _config(setup)
