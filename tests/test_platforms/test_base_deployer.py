"""Tests for shared platform deployer base class."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.models.deployment_enums import DeploymentStrategy
from opentide.platforms.base import BaseRuleDeployer


class _StubDeployer(BaseRuleDeployer):
    def __init__(self) -> None:
        self.deployed: list[str] = []

    def deploy_mdr(self, mdr, deployment_plan) -> None:
        self.deployed.append(mdr.metadata.uuid)


def test_base_rule_deployer_resolves_uuid_strings() -> None:
    deployer = _StubDeployer()
    mock_rule = MagicMock()
    mock_rule.name = "Test Rule"
    mock_rule.metadata.uuid = "uuid-1"

    with patch("opentide.core.registry.OpenTide") as mock_tide:
        mock_tide.Rules.__getitem__.return_value = mock_rule
        deployer.deploy(["uuid-1"], DeploymentStrategy.STAGING)

    assert deployer.deployed == ["uuid-1"]
