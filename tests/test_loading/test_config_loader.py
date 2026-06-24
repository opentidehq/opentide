"""Tests for configuration loader helpers."""

from __future__ import annotations

import pytest

from opentide.loading.config_loader import ConfigurationsLoader


def test_load_statuses_from_dicts() -> None:
    statuses = ConfigurationsLoader.load_statuses(
        [{"name": "preview", "description": "Preview status", "strategy": "PREVIEW"}]
    )
    assert len(statuses) == 1
    assert statuses[0].name == "preview"


def test_load_visibility_returns_none_for_empty() -> None:
    assert ConfigurationsLoader.load_visibility({}) is None


def test_load_visibility_valid_config() -> None:
    config = {
        "assets": [
            {
                "name": "workstations",
                "description": "Corporate laptops",
                "criticality": "medium",
            }
        ],
        "logsources": [
            {
                "name": "sysmon",
                "description": "Sysmon events",
                "system": "windows",
                "assets": ["workstations"],
            }
        ],
        "detectors": [],
    }
    result = ConfigurationsLoader.load_visibility(config)
    assert result is not None
    assert result.logsources[0].name == "sysmon"


def test_load_visibility_raises_on_invalid() -> None:
    with pytest.raises(ValueError, match="Failed to load visibility"):
        ConfigurationsLoader.load_visibility({"assets": "not-a-list"})
