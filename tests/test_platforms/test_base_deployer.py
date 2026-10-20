"""Tests for shared platform deployer base class."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.models.deployment_enums import StatusStrategy
from opentide.platforms.base import BaseRuleDeployer


class _StubDeployer(BaseRuleDeployer):
    def __init__(self) -> None:
        self.deployed: list[str] = []
        self.strategies: list[object] = []

    def deploy_mdr(self, mdr, strategies) -> None:
        self.deployed.append(mdr.metadata.uuid)
        self.strategies.append(strategies)


def test_base_rule_deployer_resolves_uuid_strings() -> None:
    deployer = _StubDeployer()
    mock_rule = MagicMock()
    mock_rule.name = "Test Rule"
    mock_rule.metadata.uuid = "uuid-1"

    with patch("opentide.core.registry.Opentide") as mock_tide:
        mock_tide.Rules.__getitem__.return_value = mock_rule
        deployer.deploy(["uuid-1"], (StatusStrategy.PREVIEW,))

    assert deployer.deployed == ["uuid-1"]
    assert deployer.strategies == [(StatusStrategy.PREVIEW,)]
