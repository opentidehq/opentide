import pandas as pd
from git.repo import Repo
from opentide.generation.framework import unroll_dot_dict
from opentide.models.deployment_enums import (
    DeploymentStrategy,
    DetectionPlatforms,
    StatusStrategy,
)
from opentide.models.system_config import (
    DeploymentBatch,
    SystemConfig,
    TenantDeployment,
)
from opentide.core.registry import OpenTide
from opentide.models.deployment_enums import DetectionPlatforms
from opentide.core.errors import Errors
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide, DebugHelpers
from opentide.core.logging import log
import sys
import os
import yaml
import re
from typing import MutableMapping, Sequence
from enum import Enum, auto
from pathlib import Path
from dataclasses import asdict, dataclass




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
            log(
                "FATAL",
                "CI Target environment variable is not implemented",
                "Ensure that you have configured a variable OpenTide.TargetCi as part of your pipeline",
                "Current supported values: GitlabCI, AzurePipelines, GitlabActions, LocalDebug",
            )
            raise Exception
