"""Platform registry behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock

from opentide.platforms.registry import Platform, PlatformsRegistry


def test_platforms_registry_register() -> None:
    registry = PlatformsRegistry()
    deployer = MagicMock()
    platform = registry.register("sentinel", deployer=deployer, enabled=True)
    assert platform.name == "sentinel"
    assert platform.deployer is deployer
    assert platform.enabled is True


def test_platform_can_deploy_and_validate() -> None:
    platform = Platform(name="splunk", deployer=MagicMock(), validator=None)
    assert platform.can_deploy is True
    assert platform.can_validate is False
