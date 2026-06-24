"""Extended platform plugins coverage."""

from __future__ import annotations

import warnings
from unittest.mock import MagicMock, patch

import pytest

from opentide.platforms import plugins
from opentide.platforms.plugins import (
    DeployTide,
    Platform,
    PlatformLoader,
    QueryValidator,
    RuleDeployer,
    _class_name,
    _platform_pkg,
)


def test_platform_capabilities() -> None:
    deployer = MagicMock(spec=RuleDeployer)
    validator = MagicMock(spec=QueryValidator)
    platform = Platform(
        name="sentinel",
        enabled=True,
        deployer=deployer,
        validator=validator,
    )
    assert platform.can_deploy is True
    assert platform.can_validate is True
    assert Platform(name="splunk").can_deploy is False


def test_class_name_and_platform_pkg_helpers() -> None:
    assert _class_name("defender_for_endpoint") == "DefenderForEndpoint"
    assert _platform_pkg("carbon_black_cloud") == "carbon_black"
    assert _platform_pkg("sentinel") == "sentinel"


def test_platform_loader_import_engine() -> None:
    mock_module = MagicMock()
    with patch("importlib.import_module", return_value=mock_module):
        module = PlatformLoader.import_engine("opentide.platforms.sentinel")
    assert module is mock_module


def test_platform_loader_load_engines_deploy_tier() -> None:
    loader = PlatformLoader()
    mock_module = MagicMock()
    mock_module.declare.return_value = MagicMock()
    with (
        patch.object(loader, "import_engine", return_value=mock_module),
        patch("opentide.core.registry.OpenTide") as mock_tide,
    ):
        mock_tide.Configuration.Systems.Index = ["sentinel"]
        engines = loader._load_engines(tier=plugins.PlatformEngine(), identifier="")
    assert "sentinel" in engines


def test_platform_loader_load_engines_validation_tier() -> None:
    loader = PlatformLoader()
    mock_module = MagicMock()
    mock_module.declare.return_value = MagicMock()
    with (
        patch.object(loader, "import_engine", return_value=mock_module),
        patch("opentide.core.registry.OpenTide") as mock_tide,
    ):
        mock_tide.Configuration.Systems.Index = ["splunk"]
        engines = loader._load_engines(tier=plugins.ValidationEngine(), identifier="_query")
    assert "splunk" in engines


def test_platforms_accessor_getitem_and_enabled() -> None:
    accessor = plugins.Platforms
    accessor._deployers = None
    accessor._validators = None
    accessor._instances = None
    deployer = MagicMock()
    validator = MagicMock()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        accessor._deployers = {"sentinel": deployer}
        accessor._validators = {"sentinel": validator}
        accessor._instances = {
            "sentinel": Platform(
                name="sentinel",
                enabled=True,
                deployer=deployer,
                validator=validator,
            ),
            "splunk": Platform(name="splunk", enabled=False),
        }
        assert accessor["sentinel"].name == "sentinel"
        assert list(accessor.enabled()) == [accessor._instances["sentinel"]]
        assert accessor.deployers()["sentinel"] is deployer
        assert accessor.validators()["sentinel"] is validator


def test_platforms_accessor_getattr_by_class_name() -> None:
    accessor = plugins.Platforms
    platform = Platform(name="defender_for_endpoint", enabled=True)
    accessor._instances = {"defender_for_endpoint": platform}
    accessor._deployers = {}
    accessor._validators = {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert accessor.DefenderForEndpoint is platform


def test_platforms_accessor_missing_key_raises() -> None:
    accessor = plugins.Platforms
    accessor._instances = {}
    accessor._deployers = {}
    accessor._validators = {}
    with (
        warnings.catch_warnings(),
        pytest.raises(KeyError),
    ):
        warnings.simplefilter("ignore", DeprecationWarning)
        _ = accessor["missing"]


def test_deploy_tide_filters_enabled_systems() -> None:
    deployer = MagicMock()
    validator = MagicMock()
    with (
        patch("opentide.deployment.enabled_systems", return_value=["sentinel"]),
        patch.object(
            plugins.Platforms,
            "deployers",
            return_value={"sentinel": deployer, "splunk": MagicMock()},
        ),
        patch.object(
            plugins.Platforms,
            "validators",
            return_value={"sentinel": validator, "splunk": MagicMock()},
        ),
    ):
        tide = DeployTide()
        assert tide.mdr == {"sentinel": deployer}
        assert tide.query_validation == {"sentinel": validator}
