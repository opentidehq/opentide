"""Tests for CLI enumerations."""

from __future__ import annotations

from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS, DetectionPlatform


def test_query_validation_platforms_exclude_crowdstrike_and_harfanglab() -> None:
    assert DetectionPlatform.crowdstrike.value not in QUERY_VALIDATION_PLATFORMS
    assert DetectionPlatform.harfanglab.value not in QUERY_VALIDATION_PLATFORMS


def test_query_validation_platforms_include_five_deployers() -> None:
    assert len(QUERY_VALIDATION_PLATFORMS) == 5
    assert DetectionPlatform.sentinel.value in QUERY_VALIDATION_PLATFORMS
    assert DetectionPlatform.defender.value in QUERY_VALIDATION_PLATFORMS
