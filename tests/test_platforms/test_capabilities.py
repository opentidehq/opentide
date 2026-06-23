"""Platform capability invariants."""

from __future__ import annotations

from importlib.metadata import entry_points

import pytest

from opentide.mcp_server.constants import QUERY_VALIDATION_PLATFORMS

_ALL_PLATFORMS = (
    "sentinel",
    "splunk",
    "crowdstrike",
    "defender_for_endpoint",
    "sentinel_one",
    "carbon_black_cloud",
    "harfanglab",
)


def _registered_platforms() -> set[str]:
    return {ep.name.replace("-", "_") for ep in entry_points(group="opentide.platforms")}


@pytest.mark.parametrize("platform", _ALL_PLATFORMS)
def test_platform_entry_point_registered(platform: str) -> None:
    assert platform in _registered_platforms()


@pytest.mark.parametrize("platform", ["crowdstrike", "harfanglab"])
def test_no_query_validator(platform: str) -> None:
    assert platform not in QUERY_VALIDATION_PLATFORMS


@pytest.mark.parametrize("platform", sorted(QUERY_VALIDATION_PLATFORMS))
def test_query_validator_platform(platform: str) -> None:
    assert platform in _ALL_PLATFORMS


def test_bundled_platform_config_count() -> None:
    from importlib.resources import files
    from pathlib import Path

    data_path = Path(str(files("opentide.data")))
    platforms = list((data_path / "configurations" / "platforms").glob("*.toml"))
    assert len(platforms) == 7
