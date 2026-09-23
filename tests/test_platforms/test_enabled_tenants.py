"""Tenant preflight for enabled platforms (#314)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from opentide.core.root import get_data_root, get_repo_root
from opentide.platforms.enabled import (
    SYSTEM_KEYS,
    MissingTenantsError,
    platform_config_path,
    systems_without_tenants,
)

TENANT = """
[[tenants]]
name = "Primary"
deployment = "ALWAYS"
"""


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path))
    get_data_root.cache_clear()
    get_repo_root.cache_clear()
    yield tmp_path
    get_data_root.cache_clear()
    get_repo_root.cache_clear()


def _write_config(workspace: Path, folder: str, system: str, body: str) -> Path:
    path = workspace / ".opentide" / "configurations" / folder / f"{system}.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_bundled_platform_configs_ship_without_tenants(workspace: Path) -> None:
    assert systems_without_tenants(SYSTEM_KEYS) == list(SYSTEM_KEYS)


@pytest.mark.parametrize("folder", ["platforms", "systems"])
def test_a_client_tenant_clears_only_its_platform(workspace: Path, folder: str) -> None:
    _write_config(workspace, folder, "splunk", "[platform]\nenabled = true\n" + TENANT)
    assert systems_without_tenants(["splunk", "sentinel"]) == ["sentinel"]


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("[platform]\nenabled = true\n" + TENANT.replace("\n", "\n# "), id="commented"),
        pytest.param("tenants = []\n", id="empty-list"),
        pytest.param('tenants = ["Primary"]\n', id="not-a-table"),
        pytest.param('tenants = "Primary"\n', id="not-a-list"),
    ],
)
def test_tenants_that_the_loader_would_skip_count_as_missing(workspace: Path, body: str) -> None:
    _write_config(workspace, "platforms", "splunk", body)
    assert systems_without_tenants(["splunk"]) == ["splunk"]


def test_an_unknown_system_has_no_tenants(workspace: Path) -> None:
    assert systems_without_tenants(["not_a_platform"]) == ["not_a_platform"]


def test_config_path_prefers_platforms_then_legacy_systems(workspace: Path) -> None:
    assert platform_config_path("splunk") == ".opentide/configurations/platforms/splunk.toml"
    _write_config(workspace, "systems", "splunk", "")
    assert platform_config_path("splunk") == ".opentide/configurations/systems/splunk.toml"
    _write_config(workspace, "platforms", "splunk", "")
    assert platform_config_path("splunk") == ".opentide/configurations/platforms/splunk.toml"


def test_missing_tenants_error_names_the_platform_and_its_file(workspace: Path) -> None:
    _write_config(workspace, "systems", "sentinel", "")
    error = MissingTenantsError("sentinel")
    assert isinstance(error, ValueError)
    assert error.system == "sentinel"
    assert error.config_path == ".opentide/configurations/systems/sentinel.toml"
    assert str(error) == (
        "sentinel has no tenants configured in .opentide/configurations/systems/sentinel.toml"
    )
    assert error.advice == (
        "add (or uncomment) a [[tenants]] entry in .opentide/configurations/systems/sentinel.toml"
    )


def test_missing_tenants_error_accepts_an_explicit_path() -> None:
    error = MissingTenantsError("splunk", "custom/splunk.toml")
    assert str(error) == "splunk has no tenants configured in custom/splunk.toml"
    assert error.advice == "add (or uncomment) a [[tenants]] entry in custom/splunk.toml"
