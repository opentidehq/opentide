"""Extended platform registry coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opentide.platforms.registry import Platform, PlatformsRegistry, _class_name


def test_class_name_helper() -> None:
    assert _class_name("carbon_black_cloud") == "CarbonBlackCloud"


def test_registry_register_updates_existing_platform() -> None:
    registry = PlatformsRegistry()
    deployer_v1 = MagicMock()
    deployer_v2 = MagicMock()
    registry.register("sentinel", deployer=deployer_v1, enabled=True)
    platform = registry.register("sentinel", deployer=deployer_v2, enabled=False)
    assert platform.deployer is deployer_v2
    assert platform.enabled is False


def test_registry_getitem_and_contains() -> None:
    registry = PlatformsRegistry()
    registry.register("splunk", deployer=MagicMock(), enabled=True)
    registry._loaded = True
    assert "splunk" in registry
    assert registry["splunk"].name == "splunk"


def test_registry_getattr_by_class_name() -> None:
    registry = PlatformsRegistry()
    registry.register("sentinel_one", deployer=MagicMock())
    registry._loaded = True
    assert registry.SentinelOne.name == "sentinel_one"


def test_registry_getattr_private_raises() -> None:
    registry = PlatformsRegistry()
    registry._loaded = True
    with pytest.raises(AttributeError):
        _ = registry._missing  # noqa: SLF001


def test_registry_enabled_iterator() -> None:
    registry = PlatformsRegistry()
    registry.register("sentinel", deployer=MagicMock(), enabled=True)
    registry.register("splunk", deployer=MagicMock(), enabled=False)
    registry._loaded = True
    enabled = list(registry.enabled())
    assert len(enabled) == 1
    assert enabled[0].name == "sentinel"


def test_registry_deployers_and_validators() -> None:
    registry = PlatformsRegistry()
    deployer = MagicMock()
    validator = MagicMock()
    registry.register("sentinel", deployer=deployer, validator=validator)
    registry._loaded = True
    assert registry.deployers()["sentinel"] is deployer
    assert registry.validators()["sentinel"] is validator


def test_registry_items() -> None:
    registry = PlatformsRegistry()
    registry.register("sentinel", deployer=MagicMock())
    registry._loaded = True
    items = dict(registry.items())
    assert "sentinel" in items


def test_registry_load_validator_returns_none_for_unknown() -> None:
    registry = PlatformsRegistry()
    assert registry._load_validator("crowdstrike") is None


def test_registry_load_validator_falls_back_to_platform_package() -> None:
    registry = PlatformsRegistry()
    mock_validator = MagicMock()
    mock_module = MagicMock()
    mock_module.declare.return_value = mock_validator

    def _import(name: str) -> MagicMock:
        if name.startswith("opentide.validation"):
            raise ModuleNotFoundError(name)
        if name == "opentide.platforms.sentinel.validator":
            return mock_module
        raise ModuleNotFoundError(name)

    with patch("importlib.import_module", side_effect=_import):
        result = registry._load_validator("sentinel")
    assert result is mock_validator


def test_registry_load_validator_imports_module() -> None:
    registry = PlatformsRegistry()
    mock_validator = MagicMock()
    mock_module = MagicMock()
    mock_module.declare.return_value = mock_validator
    with patch("importlib.import_module", return_value=mock_module):
        result = registry._load_validator("sentinel")
    assert result is mock_validator


def test_registry_ensure_loaded_from_entry_points() -> None:
    registry = PlatformsRegistry()
    mock_ep = MagicMock()
    mock_ep.name = "sentinel"
    mock_ep.load.return_value = MagicMock(return_value=MagicMock())
    with (
        patch("opentide.platforms.registry.entry_points", return_value=[mock_ep]),
        patch("opentide.platforms.registry.enabled_systems", return_value=["sentinel"]),
        patch("opentide.platforms.registry.build_system_config", return_value={"host": "x"}),
        patch.object(registry, "_load_validator", return_value=MagicMock()),
    ):
        registry._ensure_loaded()
    assert registry._loaded is True
    assert "sentinel" in registry._instances


def test_platform_can_validate_property() -> None:
    platform = Platform(name="splunk", validator=MagicMock())
    assert platform.can_validate is True
    assert Platform(name="splunk").can_validate is False
