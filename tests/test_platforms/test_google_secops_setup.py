"""Google SecOps tenant setup (google-secops-1.0, Tenant setup)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from opentide.core.io import load_toml
from opentide.models.configuration.platforms import (
    PLATFORM_CONFIGURATION_MODELS,
    GoogleSecopsConfiguration,
)
from opentide.platforms.config import build_system_config
from opentide.platforms.google_secops.client import GoogleSecopsClient

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

BUNDLED = Path(__file__).resolve().parents[2] / "src/opentide/data/configurations/platforms"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "google_secops" / "tenant.toml"
INSTANCE = "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6"


def _config(setup: dict[str, Any]) -> Any:
    raw = {"platform": {"enabled": True}, "tenants": [{"name": "secops", "setup": setup}]}
    return build_system_config("google_secops", raw)


def _setup(**keys: Any) -> dict[str, Any]:
    return {"project": "acme-secops", "location": "eu", "instance": INSTANCE, **keys}


def test_the_bundled_file_is_off_and_has_no_tenant() -> None:
    raw = load_toml(BUNDLED / "google_secops.toml")
    assert raw["platform"]["enabled"] is False
    assert raw["platform"]["name"] == "Google Security Operations"
    assert "tenants" not in raw
    assert build_system_config("google_secops", raw).tenants is None


def test_the_specification_tenant_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SECOPS_CREDENTIALS", "/secrets/key.json")
    raw = tomllib.loads(FIXTURE.read_text(encoding="utf-8"))
    # The fixture's [platform] table carries identifier, subschema and flags, which
    # opentide's shared platform identity does not take on any platform.
    for key in ("identifier", "subschema", "flags"):
        del raw["platform"][key]
    (tenant,) = build_system_config("google_secops", raw).tenants
    assert tenant.setup.credentials == "/secrets/key.json"
    assert tenant.setup.deletion == "archive"
    assert tenant.setup.endpoint is None
    assert tenant.strategies is not None
    assert PLATFORM_CONFIGURATION_MODELS["google_secops"] is GoogleSecopsConfiguration
    GoogleSecopsConfiguration.model_validate(raw)


def test_defaults_and_braced_references(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECOPS_KEY", raising=False)
    (tenant,) = _config(_setup(credentials="${SECOPS_KEY}")).tenants
    # An unset variable stays its placeholder; the client refuses it.
    assert tenant.setup.credentials == "$SECOPS_KEY"
    assert tenant.setup.deletion == "archive"
    assert tenant.setup.data_access_scope is None
    (adc,) = _config(_setup()).tenants
    assert adc.setup.credentials is None


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ({"location": "eu", "instance": INSTANCE}, "missing required key\\(s\\): project"),
        (_setup(instance=""), "missing required key\\(s\\): instance"),
        (_setup(credentials='{"type": "service_account"}'), "credentials must be an environment"),
        (_setup(api_key="$K"), "unknown key\\(s\\): api_key"),
        (_setup(deletion="purge"), "deletion must be archive or delete"),
    ],
)
def test_a_bad_tenant_fails_configuration_load(setup: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _config(setup)


def test_the_client_reaches_the_regional_endpoint_or_the_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opentide.platforms.google_secops.client as client_module

    monkeypatch.setattr(client_module, "load_credentials", lambda value: object())
    (tenant,) = _config(_setup(ssl=False)).tenants
    client = GoogleSecopsClient.for_tenant(tenant)
    assert client.base == (
        f"https://eu-chronicle.googleapis.com/v1/projects/acme-secops/locations/eu/instances/"
        f"{INSTANCE}"
    )
    assert client.session.verify is False
    (custom,) = _config(_setup(endpoint="https://secops.example/")).tenants
    assert GoogleSecopsClient.for_tenant(custom).base.startswith("https://secops.example/v1/")


def test_an_unset_project_variable_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECOPS_PROJECT", raising=False)
    (tenant,) = _config(_setup(project="$SECOPS_PROJECT")).tenants
    with pytest.raises(ValueError, match="SECOPS_PROJECT"):
        GoogleSecopsClient.for_tenant(tenant)
