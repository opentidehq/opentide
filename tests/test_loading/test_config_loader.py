"""ConfigurationsLoader visibility and deployment helpers."""

from __future__ import annotations

import pytest

from opentide.loading.config_loader import ConfigurationsLoader
from opentide.models.visibility import VisibilityConfig


def test_load_statuses_typed() -> None:
    statuses = ConfigurationsLoader.load_statuses(
        [{"name": "production", "description": "Live", "strategy": "RELEASE"}]
    )
    assert statuses[0].name == "production"


def test_load_visibility_empty_returns_none() -> None:
    assert ConfigurationsLoader.load_visibility({}) is None


def test_load_visibility_minimal() -> None:
    config = {
        "logsources": [
            {
                "name": "windows",
                "description": "Windows events",
                "system": "sentinel",
            }
        ]
    }
    loaded = ConfigurationsLoader.load_visibility(config)
    assert isinstance(loaded, VisibilityConfig)
    assert loaded.logsources[0].name == "windows"


def test_load_visibility_warns_on_unknown_asset_refs() -> None:
    config = {
        "assets": [{"name": "server", "description": "Host", "criticality": "high"}],
        "logsources": [
            {
                "name": "windows",
                "description": "Windows events",
                "system": "sentinel",
                "assets": ["missing-host"],
            }
        ],
        "detectors": [
            {
                "name": "edr",
                "description": "EDR alerts",
                "assets": ["missing-host"],
            }
        ],
    }
    loaded = ConfigurationsLoader.load_visibility(config)
    assert loaded is not None
    assert loaded.logsources[0].assets == ["missing-host"]


def test_load_visibility_invalid_required_field_raises() -> None:
    with pytest.raises(ValueError, match="Failed to load visibility configuration"):
        ConfigurationsLoader.load_visibility(
            {
                "logsources": [
                    {
                        "name": "windows",
                        "description": "Windows events",
                        # missing required system field
                    }
                ]
            }
        )
