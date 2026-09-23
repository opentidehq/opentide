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


def test_registry_validator_factory_returns_none_for_unknown() -> None:
    registry = PlatformsRegistry()
    assert registry._validator_factory("crowdstrike") is None


def test_registry_validator_factory_falls_back_to_platform_package() -> None:
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
        factory = registry._validator_factory("sentinel")
    assert factory is not None
    mock_module.declare.assert_not_called()
    assert factory() is mock_validator


def test_registry_validator_factory_skips_module_without_declare() -> None:
    registry = PlatformsRegistry()
    fallback = MagicMock()

    def _import(name: str) -> object:
        if name == "opentide.validation.sentinel_query":
            return object()
        return fallback

    with patch("importlib.import_module", side_effect=_import):
        assert registry._validator_factory("sentinel") is fallback.declare


def test_registry_ensure_loaded_from_entry_points() -> None:
    registry = PlatformsRegistry()
    deployer = MagicMock()
    declare = MagicMock(return_value=deployer)
    mock_ep = MagicMock()
    mock_ep.name = "sentinel"
    mock_ep.load.return_value = declare
    build = MagicMock(return_value={"host": "x"})
    validator_factory = MagicMock()
    with (
        patch("opentide.platforms.registry.entry_points", return_value=[mock_ep]),
        patch("opentide.platforms.registry.enabled_systems", return_value=["sentinel"]),
        patch("opentide.platforms.registry.build_system_config", build),
        patch.object(registry, "_validator_factory", return_value=validator_factory),
    ):
        registry._ensure_loaded()
        platform = registry._instances["sentinel"]
        assert platform.enabled is True
        assert platform.can_deploy is True
        assert platform.can_validate is True
        declare.assert_not_called()
        validator_factory.assert_not_called()
        build.assert_not_called()
        assert platform.deployer is deployer
        assert platform.config == {"host": "x"}
    assert registry._loaded is True
    build.assert_called_once_with("sentinel")


def test_platform_builds_each_engine_once() -> None:
    factory = MagicMock(return_value=MagicMock())
    platform = Platform(name="splunk", deployer_factory=factory)
    factory.assert_not_called()
    assert platform.deployer is platform.deployer
    factory.assert_called_once_with()


def test_platform_engine_that_fails_to_build_is_unavailable() -> None:
    platform = Platform(name="splunk", validator_factory=MagicMock(side_effect=KeyError("url")))
    assert platform.can_validate is True
    assert platform.validator is None
    assert platform.can_validate is False


def test_platform_can_validate_property() -> None:
    platform = Platform(name="splunk", validator=MagicMock())
    assert platform.can_validate is True
    assert Platform(name="splunk").can_validate is False
