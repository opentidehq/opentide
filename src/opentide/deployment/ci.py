import os
from typing import Any

from opentide.core.logging import get_logger
from opentide.core.registry import DebugHelpers
from opentide.models.deployment_enums import (
    StatusStrategy,
)

logger = get_logger(__name__)
from enum import Enum, auto

DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)


def __getattr__(name: str) -> Any:
    """Resolve registry-backed globals on access rather than at import (#536).

    Evaluating this at module level built the whole registry index as an import
    side effect, and bound whatever ``opentide.core.registry.Opentide`` happened
    to be at the time -- so a module first imported under ``patch()`` kept the
    mock permanently.
    """
    if name == "SYSTEMS_CONFIGS_INDEX":
        from opentide.core import registry

        return registry.Opentide.Configurations.Systems.Index
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class CIEnvironment:
    """
    Returns the CI Environment based on the environment variables
    """

    def __init__(self):
        self.environment = self._check_ci_environment()

    class CIPlatforms(Enum):
        """
        Represents the supported CI options
        """

        AzurePipeline = auto()
        GitlabCI = auto()
        GitHubActions = auto()
        LocalDebug = auto()

    def _check_ci_environment(self) -> CIPlatforms:
        if os.getenv("TF_BUILD"):
            logger.info("discovered_ci_environment", platform="azure_pipeline")
            return self.CIPlatforms.AzurePipeline
        elif os.getenv("GITHUB_ACTIONS"):
            logger.info("discovered_ci_environment", platform="github_actions")
            return self.CIPlatforms.GitHubActions
        elif os.getenv("CI"):
            logger.info("discovered_ci_environment", platform="gitlab_ci")
            return self.CIPlatforms.GitlabCI
        elif DebugHelpers.is_debug():
            logger.info("discovered_ci_environment", platform="local")
            return self.CIPlatforms.LocalDebug
        else:
            logger.info("discovered_ci_environment", platform="local")
            return self.CIPlatforms.LocalDebug


def __dir__() -> list[str]:
    return sorted(set(globals()) | {"SYSTEMS_CONFIGS_INDEX"})
