"""Shared deployer composition for platform implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from opentide.core.logging import get_logger
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule

logger = get_logger(__name__)


class BaseRuleDeployer(ABC):
    """Template-method deployer shared by platform deployer classes."""

    @abstractmethod
    def deploy_mdr(
        self,
        mdr: DetectionRule,
        deployment_plan: DeploymentStrategy | None,
    ) -> None:
        """Deploy a single rule onto the target platform."""

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        """Deploy rules, resolving UUID strings to loaded models when needed."""
        rules = self._resolve_rules(mdr_deployment)
        for mdr in rules:
            logger.info(
                "deploying_rule",
                rule=mdr.name,
                uuid=mdr.metadata.uuid,
                plan=str(deployment_plan),
            )
            self.deploy_mdr(mdr, deployment_plan)

    def _resolve_rules(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
    ) -> list[DetectionRule]:
        from opentide.core.registry import OpenTide

        if not mdr_deployment:
            return []
        first = mdr_deployment[0]
        if isinstance(first, DetectionRule):
            return list(mdr_deployment)  # type: ignore[arg-type]
        return [OpenTide.Rules[uuid] for uuid in mdr_deployment]  # type: ignore[index]
