from opentide.models.deployment_enums import (
    StatusStrategy,
)
from opentide.core.registry import OpenTide
from opentide.core.registry import OpenTide, DebugHelpers
from opentide.core.logging import log
import os
from enum import Enum, auto




SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION,
                        StatusStrategy.DISABLEMENT)

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
            log("SUCCESS", "Discovered CI Environment to be Azure Pipeline")
            return self.CIPlatforms.AzurePipeline
        elif os.getenv("GITHUB_ACTIONS"):
            log("SUCCESS", "Discovered CI Environment to be GitHub Actions")
            return self.CIPlatforms.GitHubActions
        elif os.getenv("CI"):
            log("SUCCESS", "Discovered CI Environment to be Gitlab CI")
            return self.CIPlatforms.GitlabCI
        elif DebugHelpers.is_debug():
            log("SUCCESS", "Discover CI Environment to be Local")
            return self.CIPlatforms.LocalDebug
        else:
            log("SUCCESS", "Discover CI Environment to be Local")
            return self.CIPlatforms.LocalDebug
