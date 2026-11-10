"""Bitdefender tenant setup (bitdefender-1.0, Tenant setup)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from opentide.core.io import load_toml
from opentide.models.configuration.platforms import (
    PLATFORM_CONFIGURATION_MODELS,
    BitdefenderConfiguration,
)
from opentide.platforms.config import build_system_config

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

BUNDLED = Path(__file__).resolve().parents[2] / "src/opentide/data/configurations/platforms"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "bitdefender" / "tenant.toml"
TAG = "5b680f6fb1a43d860a7b23c8"
COMPANY = "61827b8036492c2fc0718722"


def _config(setup: dict[str, Any]) -> Any:
    raw = {"platform": {"enabled": True}, "tenants": [{"name": "gz", "setup": setup}]}
    return build_system_config("bitdefender", raw)


def _setup(**keys: Any) -> dict[str, Any]:
    return {"url": "https://cloudgz.gravityzone.bitdefender.com/api", "api_key": "$GZ_KEY", **keys}


def test_the_bundled_file_is_off_and_has_no_tenant() -> None:
    raw = load_toml(BUNDLED / "bitdefender.toml")
    assert raw["platform"]["enabled"] is False
    assert raw["platform"]["name"] == "Bitdefender GravityZone"
    assert "tenants" not in raw
    assert build_system_config("bitdefender", raw).tenants is None


def test_the_specification_tenant_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAVITYZONE_API_KEY", "resolved")
    raw = tomllib.loads(FIXTURE.read_text(encoding="utf-8"))
    # The fixture's [platform] table carries identifier, subschema and flags, which
    # opentide's shared platform identity does not take on any platform.
    for key in ("identifier", "subschema", "flags"):
        del raw["platform"][key]
    (tenant,) = build_system_config("bitdefender", raw).tenants
    assert tenant.setup.api_key == "resolved"
    assert tenant.setup.key_type == "personal"
    assert tenant.setup.tags == ["managed-by-opentide"]
    assert tenant.setup.endpoint_tags == {"tier0-servers": {"tag_id": TAG, "company_id": COMPANY}}
    assert PLATFORM_CONFIGURATION_MODELS["bitdefender"] is BitdefenderConfiguration
    BitdefenderConfiguration.model_validate(raw)


def test_defaults() -> None:
    (tenant,) = _config(_setup()).tenants
    assert tenant.setup.key_type == "personal"
    assert tenant.setup.automatic_actions is True
    assert tenant.setup.company_id is None


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ({"api_key": "$K"}, "missing required key\\(s\\): url"),
        ({"url": "https://x/api"}, "missing required key\\(s\\): api_key"),
        (_setup(api_key="literal-key"), "api_key must be an environment variable"),
        (_setup(policies=["p"]), "unknown key\\(s\\): policies"),
        (_setup(key_type="oauth"), "key_type must be personal or service"),
        (_setup(company_id="ABC"), "company_id must be a GravityZone id"),
        (_setup(companies={"acme": "1234"}), "companies.acme must be a GravityZone id"),
        (
            _setup(endpoint_tags={"t": {"tag_id": TAG.upper(), "company_id": COMPANY}}),
            "endpoint_tags.t.tag_id must be a GravityZone id",
        ),
        (_setup(endpoint_tags={"t": {"tag_id": TAG}}), "endpoint_tags.t must be"),
        (_setup(targets={"endpoint_tags": []}), "targets must be"),
        (_setup(targets={"endpoint_tags": ["a"], "companies": ["b"]}), "targets must be"),
    ],
)
def test_a_bad_tenant_fails_configuration_load(setup: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _config(setup)
