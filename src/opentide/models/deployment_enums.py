import os
from enum import Enum, auto
import structlog
logger = structlog.get_logger('opentide.models.deployment_enums')

class StatusStrategy(Enum):
    INERT = 'Does not interact with deployment'
    RELEASE = 'Deployment from the default branch (also called trunk, or main branch)'
    PREVIEW = 'Deployment from Pull/Merge Requests'
    DISABLEMENT = 'Deployment from the default branch, but only to disable an existing rule. If the target system does not have a concept of disabling rules, then defaults to deleting them.'
    DELETION = 'Deployment from the default branch, but removes the rule from the target system.'
    UNIVERSAL = 'Deployment from both Pull/Merge Requests, and default branch pipelines.'

class DetectionPlatforms(Enum):
    DEFENDER_FOR_ENDPOINT = auto()
    CARBON_BLACK_CLOUD = auto()
    SPLUNK = auto()
    SENTINEL = auto()
    SENTINEL_ONE = auto()
    CROWDSTRIKE = auto()
    HARFANGLAB = auto()
DetectionSystems = DetectionPlatforms

class DeploymentStrategy(Enum):
    STAGING = 'Deployment allowed during a Pull (or Merge) Request Pipeline'
    PRODUCTION = 'Deployment allowed during a Default Branch Pipeline'
    FULL = 'Deployment allowed during both Pull (or Merge) Request Pipeline and Default Branch Pipeline'
    ALWAYS = 'Deployment allowed during both Pull (or Merge) Request Pipeline and Default Branch Pipeline'
    MANUAL = 'Deployment allowed during both Pull (or Merge) Request Pipeline and Default Branch Pipeline, but only when explictely specified under tenants'
    DEBUG = 'Deployment used for debugging and testing purposes only'

    @staticmethod
    def load_from_environment():
        """Map DEPLOYMENT_PLAN to a DeploymentStrategy.

        An unset or empty variable defaults to FULL so local CLI usage
        (deploy --dry-run, validate query) does not require CI secrets.
        Illegal names raise ValueError with a supported-plan list.
        """
        supported = [plan.name for plan in DeploymentStrategy]
        raw = os.getenv('DEPLOYMENT_PLAN')
        if raw is None or not str(raw).strip():
            logger.info('deployment_plan_defaulting_to_full')
            return DeploymentStrategy.FULL
        name = str(raw).strip().upper()
        try:
            return DeploymentStrategy[name]
        except KeyError as exc:
            logger.critical('the_following_deployment_plan_is_not_supported', arg0=raw, advice=f'Supported plan : {supported}')
            raise ValueError(
                f"Unsupported deployment plan {raw!r}. Use one of: {', '.join(supported)}"
            ) from exc
