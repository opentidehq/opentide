import pandas as pd
from git.repo import Repo
from opentide.generation.framework import unroll_dot_dict
from opentide.models.legacy import SharedModels, TideModels, SystemConfig, DeploymentStrategy, StatusStrategy, TenantDeployment, DeploymentBatch
from opentide.core.registry import OpenTide
from opentide.models.legacy import DetectionPlatforms
from opentide.core.errors import Errors
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide, DebugHelpers
import sys
import os
import yaml
import re
from typing import MutableMapping, Sequence
from enum import Enum, auto
from pathlib import Path
from dataclasses import asdict, dataclass
import structlog
logger = structlog.get_logger('opentide.deployment.ci')
SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)

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
        if os.getenv('TF_BUILD'):
            logger.info('discovered_ci_environment_to_be_azure_pipeline')
            return self.CIPlatforms.AzurePipeline
        elif os.getenv('GITHUB_ACTIONS'):
            logger.info('discovered_ci_environment_to_be_github_actions')
            return self.CIPlatforms.GitHubActions
        elif os.getenv('CI'):
            logger.info('discovered_ci_environment_to_be_gitlab_ci')
            return self.CIPlatforms.GitlabCI
        elif DebugHelpers.is_debug():
            logger.info('discover_ci_environment_to_be_local')
            return self.CIPlatforms.LocalDebug
        else:
            logger.critical('ci_target_environment_variable_is_not_implemented', detail='Ensure that you have configured a variable OpenTide.TargetCi as part of your pipeline', advice='Current supported values: GitlabCI, AzurePipelines, GitlabActions, LocalDebug')
            raise Exception
