import pandas as pd
from git.repo import Repo
from opentide.generation.framework import unroll_dot_dict
from opentide.models.legacy import SharedModels, TideModels, SystemConfig, DeploymentStrategy, StatusStrategy, TenantDeployment, DeploymentBatch
from opentide.core.registry import OpenTide, DetectionPlatforms, ObjectLoader
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
logger = structlog.get_logger('opentide.deployment.utils')
SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)
from opentide.core.registry import OpenTide, DebugHelpers
from opentide.models.legacy import StatusStrategy, DeploymentStrategy
from opentide.deployment.ci import CIEnvironment
from opentide.deployment.git_repo import GitRepository, modified_mdr_files, diff_calculation
SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)

def check_status(status_name: str) -> StatusStrategy:
    statuses_definitions = OpenTide.Configurations.Deployment.statuses
    for status in statuses_definitions:
        if status.name == status_name:
            if type(status.strategy) is str:
                return StatusStrategy[status.name]
            elif type(status.strategy) is StatusStrategy:
                return status.strategy
            else:
                logger.critical('could_not_return_status_strategy', detail=str(status), advice=str(type(status.strategy)))
                raise Exception
    logger.critical('could_not_look_up_requested_status_in_existing_statuses', detail=f'Requested status : {status_name}', advice=f'Available statuses in deployment.toml : {statuses_definitions}')
    raise Exception

def make_deploy_plan(plan: DeploymentStrategy, wide_scope=False, keep_deprecated=True) -> dict[str, list[str]]:
    """
    Algorithm which assembles the MDR to deploy, organized per system

    plan: Execution environment used to calculate the acceptable statuses
    wide_scope: If set to true, will return all statuses regardless of the plan.

    plan is still required if wide_scope is set to True as it configures the calculation
    algorithm behaviour. wide_scope is useful to validate all MDR regardless of statuses if
    using the deploy plan to calculate the MDR that were modified.
    """
    SYSTEMS_DEPLOYMENT = enabled_systems()
    logger.info('compiling_mdrs_to_deploy_in_plan', detail=plan.name)
    if wide_scope:
        logger.warning('wide_scope_has_been_enabled_for_the_deployment_plan_calculation', detail='This will assemble the plan with no consideration for statuses. Use with caution.')
    mdr_files = list()
    deploy_mdr = dict()
    if plan == 'FULL':
        MDR_PATH = Path(OpenTide.Configurations.Global.Paths.Tide.mdr)
        mdr_files = [MDR_PATH / mdr for mdr in os.listdir(MDR_PATH)]
        logger.info('redeploying_complete_mdr_library', detail=f'[{len(mdr_files)} MDR] are in scope')
    else:
        mdr_files = modified_mdr_files(plan)
    for rule in mdr_files:
        data = yaml.safe_load(open(rule, encoding='utf-8'))
        name = data['name']
        conf_data = data['configurations']
        mdr_uuid = data.get('uuid') or data['metadata']['uuid']
        for system in conf_data:
            platform_status = conf_data[system]['status']
            if system in SYSTEMS_DEPLOYMENT:
                if keep_deprecated is False and check_status(platform_status) in DEPRECATED_STATUSES:
                    logger.info('skipped', detail=f'Not keeping in deployment plan as {system} is set to a deprecated status', arg0=platform_status)
                elif wide_scope:
                    deploy_mdr.setdefault(system, []).append(mdr_uuid)
                elif plan is DeploymentStrategy.PRODUCTION:
                    if check_status(platform_status) is StatusStrategy.RELEASE or check_status(platform_status) is StatusStrategy.UNIVERSAL or check_status(platform_status) is StatusStrategy.DISABLEMENT or (check_status(platform_status) is StatusStrategy.DELETION):
                        deploy_mdr.setdefault(system, []).append(mdr_uuid)
                        logger.info('step_completed', detail=f'[{system.upper()}][{platform_status}] Identified MDR to deploy in {plan}', arg0=name)
                    else:
                        logger.warning('event', detail=f'[{system.upper()}][{platform_status}] Skipping as cannot be deployed in {plan}', arg0=name)
                elif plan is DeploymentStrategy.STAGING:
                    if check_status(platform_status) is StatusStrategy.PREVIEW or check_status(platform_status) is StatusStrategy.UNIVERSAL:
                        deploy_mdr.setdefault(system, []).append(mdr_uuid)
                        logger.info('step_completed', detail=f'[{system.upper()}][{platform_status}] Identified MDR to deploy in {plan}', arg0=name)
                    else:
                        logger.warning('event', detail=f'[{system.upper()}][{platform_status}] Skipping as cannot be deployed in {plan}', arg0=name)
            else:
                logger.error('operation_failed', detail=f'[{system.upper()}] is disabled and cannot be deployed to for', arg0=name)
    return deploy_mdr

def modified_mdr_files(plan: DeploymentStrategy) -> list[Path]:
    MDR_PATH = Path(OpenTide.Configurations.Global.Paths.Tide.mdr)
    MDR_PATH_RAW = OpenTide.Configurations.Global.Paths.Tide._raw['mdr']
    MDR_PATH_RAW = MDR_PATH_RAW.replace('/', '\\/')
    mdr_path_regex = f'^.*{MDR_PATH_RAW}[^\\/]+(\\.yaml|\\.yml)$'
    mdr_files = [mdr.split('/')[-1] for mdr in diff_calculation(plan) if re.match(mdr_path_regex, mdr)]
    mdr_files = [MDR_PATH / Path(f) for f in mdr_files]
    logger.info('computed_modified_mdr_files', detail=str(mdr_files))
    return mdr_files

def diff_calculation(plan: DeploymentStrategy) -> list:
    """
    Calculates the files in scope of deployment based on the execution context.

    Limitation: Tied to certain Gitlab CI variables, need more separation
    to work in other environments

    In a Merge Request, the calculation will take in consideration
    the root of the MR and tip of the branch. In a direct commit to main, it will
    instead take the difference between the two last commits.

    stage: used to filter the paths computed

    """
    scope = list()
    TARGET_CI = CIEnvironment().environment
    repo = GitRepository().repository
    match TARGET_CI:
        case CIEnvironment.CIPlatforms.GitHubActions:
            logger.info('identified_github_actions_as_the_ci_runtime_platform')
            LATEST_COMMIT = os.getenv('GITHUB_SHA')
            if plan is DeploymentStrategy.PRODUCTION:
                commits = list(repo.iter_commits('HEAD', max_count=2))
                if len(commits) > 1:
                    BASE_COMMIT = commits[1].hexsha
                else:
                    return []
            elif plan is DeploymentStrategy.STAGING:
                repo.remotes.origin.fetch()
                source_branch = os.getenv('GITHUB_HEAD_REF')
                target_branch = os.getenv('GITHUB_BASE_REF')
                if not source_branch or not target_branch:
                    logger.critical('could_not_identify_source_and_target_branch_using_predefined_azu', detail='Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME', advice='Ensure this is runnning in a Pull Request pipeline')
                    raise KeyError
                source_branch = source_branch.replace('refs/heads/', '')
                source_branch = 'origin/' + source_branch
                target_branch = 'origin/' + target_branch
                logger.info('identified_source_and_target_branch_in_the_pull_request', detail=f'source: {source_branch} -> target: {target_branch}')
                base_commit = repo.merge_base(target_branch, source_branch)
                if base_commit[0]:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    logger.critical('could_not_identify_the_base_of_the_pull_request', detail='You may not have a sufficient Checkout Depth configuration', advice='If you run very old Pull Requests, this setting may need to be increased, or reopen a PR')
                    raise Errors
        case CIEnvironment.CIPlatforms.GitlabCI:
            logger.info('identified_gitlab_ci_as_the_ci_runtime_platform')
            LATEST_COMMIT = os.getenv('CI_COMMIT_SHA')
            if plan is DeploymentStrategy.PRODUCTION:
                BASE_COMMIT = os.getenv('CI_COMMIT_BEFORE_SHA')
            elif plan is DeploymentStrategy.STAGING:
                BASE_COMMIT = os.getenv('CI_MERGE_REQUEST_DIFF_BASE_SHA')
                if os.getenv('CI_MERGE_REQUEST_EVENT_TYPE') == 'merged_result':
                    logger.info('currently_running_a_diff_calculation_for_merge_results')
                    for commit in repo.iter_commits():
                        if commit.hexsha == os.getenv('CI_COMMIT_BEFORE_SHA'):
                            mr_correct_parent = commit.parents[1]
                            logger.info('current_evaluating_commit_and_found_parent', detail=f'{commit.hexsha} | {commit.message}', advice=str(mr_correct_parent))
                            LATEST_COMMIT = mr_correct_parent
                            break
            else:
                logger.critical('fatal_error', detail=f'Illegal Deployment Plan {plan!s} passed to diff_calculation algorithm')
                raise KeyError
        case CIEnvironment.CIPlatforms.AzurePipeline:
            logger.info('identified_azure_pipeline_as_the_ci_runtime_platform')
            LATEST_COMMIT = os.getenv('BUILD_SOURCEVERSION')
            if plan is DeploymentStrategy.PRODUCTION:
                commits = list(repo.iter_commits('HEAD', max_count=2))
                if len(commits) > 1:
                    BASE_COMMIT = commits[1].hexsha
                else:
                    return []
            elif plan is DeploymentStrategy.STAGING:
                repo.remotes.origin.fetch()
                source_branch = os.getenv('SYSTEM_PULLREQUEST_SOURCEBRANCH')
                target_branch = os.getenv('SYSTEM_PULLREQUEST_TARGETBRANCHNAME')
                if not source_branch or not target_branch:
                    logger.critical('could_not_identify_source_and_target_branch_using_predefined_azu', detail='Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME', advice='Ensure this is runnning in a Pull Request pipeline')
                    raise KeyError
                source_branch = source_branch.replace('refs/heads/', '')
                source_branch = 'origin/' + source_branch
                target_branch = 'origin/' + target_branch
                logger.info('identified_source_and_target_branch_in_the_pull_request', detail=f'source: {source_branch} -> target: {target_branch}')
                base_commit = repo.merge_base(target_branch, source_branch)
                if base_commit[0]:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    logger.critical('could_not_identify_the_base_of_the_pull_request', detail='You may not have a sufficient OpenTide.Repo.Checkout.Depth configuration', advice='If you run very old Pull Requests, this setting may need to be increased, or reopen a PR')
                    raise Errors
            else:
                logger.critical('fatal_error', detail=f'Illegal Deployment Plan {plan!s} passed to diff_calculation algorithm')
                raise KeyError
        case _:
            logger.critical('illegal_ci_environment_detected', detail=str(TARGET_CI))
            raise Exception
    logger.info('setting_source_and_target_commit_for_the_diff_calculation_to', detail=f'{BASE_COMMIT} | {LATEST_COMMIT}')
    source_commit = None
    try:
        source_commit = repo.commit(BASE_COMMIT)
    except Exception:
        logger.info('could_not_find_source_commit_in_current_branch_trying_iter_commi')
        remote_refs = repo.remote().refs
        for refs in remote_refs:
            logger.info('event', detail=refs.name)
        for commit in repo.iter_commits('origin/main'):
            logger.info('currently_evaluating', detail=f'{commit.message}')
            if commit.hexsha == BASE_COMMIT:
                source_commit = commit
                logger.info('found_source_commit', detail=f'{commit.hexsha} | {commit.message}')
                break
    if not source_commit:
        logger.critical('no_source_commit_could_be_identified')
        raise Exception('No Source Commit Found')
    latest_commit = repo.commit(LATEST_COMMIT)
    diff = source_commit.diff(latest_commit)
    logger.info('preliminary_diff_calculation_completed_returned_with', detail=', '.join([f.b_path for f in diff]))
    added_files = [f.b_path for f in diff.iter_change_type('A')]
    renamed_files = [f.b_path for f in diff.iter_change_type('R')]
    modified_files = [f.b_path for f in diff.iter_change_type('M')]
    scope = added_files + renamed_files + modified_files
    scope = list(set(scope))
    logger.info('computed_diff_scope', detail=', '.join(scope))
    return scope

def enabled_systems() -> list[str]:
    enabled_systems = list()
    for system in SYSTEMS_CONFIGS_INDEX:
        try:
            if SYSTEMS_CONFIGS_INDEX[system]['tide'].get('enabled') is True:
                enabled_systems.append(system)
        except:
            if SYSTEMS_CONFIGS_INDEX[system]['platform'].get('enabled') is True:
                enabled_systems.append(system)
    return enabled_systems

class Proxy:
    """
    Encapsulates proxy setup for environment variables.

    Behavior:
    - Requires proxy_host and proxy_port
    - Uses proxy_user / proxy_password only when both are provided
    - Supports unauthenticated proxy URLs for hosts behind transparent proxies
    """

    @staticmethod
    def set_proxy():
        if DebugEnvironment.ENABLED and (not DebugEnvironment.PROXY_ENABLED):
            return
        logger.info('setting_environment_proxy_according_to_ci_variables')
        PROXY_CONFIG = OpenTide.Configurations.Deployment.proxy
        PROXY_CONFIG = DebugHelpers.fetch_config_envvar(PROXY_CONFIG)
        proxy_user = PROXY_CONFIG.get('proxy_user')
        proxy_pass = PROXY_CONFIG.get('proxy_password')
        proxy_host = PROXY_CONFIG.get('proxy_host')
        proxy_port = PROXY_CONFIG.get('proxy_port')
        if proxy_host and proxy_port:
            if proxy_user and proxy_pass:
                proxy = f'http://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}'
            else:
                proxy = f'http://{proxy_host}:{proxy_port}'
            os.environ['HTTP_PROXY'] = proxy
            os.environ['HTTPS_PROXY'] = proxy
            logger.info('proxy_environment_setup_successful')
        else:
            logger.error('could_not_retrieve_mandatory_proxy_host_and_port', detail='Control that proxy_host and proxy_port are entered in CI variables', advice='proxy_user and proxy_password are optional')

    @staticmethod
    def unset_proxy():
        os.environ['HTTP_PROXY'] = ''
        os.environ['HTTPS_PROXY'] = ''
        logger.info('resetting_proxy_setup')

class ExternalIdHelper:
    """
    Utility class to help processing external rule IDs in MDR Files
    """

    @staticmethod
    def remove_id(rule_id: int | str, tenant_name: str, mdr_uuid: str):
        """
        Removes an existing external ID. Mostly used in rule deletion workflows
        """
        file_path = OpenTide.Configurations.Global.Paths.Tide.mdr / OpenTide.Models.files[mdr_uuid]
        with open(file_path, 'r', encoding='utf-8') as mdr_file:
            content = mdr_file.readlines()
        updated_content = list()
        for line in content:
            if line.strip() != f'rule_id::{tenant_name}: {rule_id}':
                updated_content.append(line)
        with open(file_path, 'w', encoding='utf-8') as mdr_file:
            logger.info('step_completed', detail=f'Removed ID in MDR File for tenant {tenant_name}')
            mdr_file.writelines(updated_content)

    @staticmethod
    def insert_id(rule_id: int | str, tenant_name: str, mdr_uuid: str, system_name: str):
        """
        Adds a new rule_id::<tenant>::<id> key to store IDs generated by the target system
        """
        file_path = OpenTide.Configurations.Global.Paths.Tide.mdr / OpenTide.Models.files[mdr_uuid]
        with open(file_path, 'r', encoding='utf-8') as mdr_file:
            content = mdr_file.readlines()
        updated_content = list()
        for line in content:
            if line.strip().removesuffix(':').strip() == system_name:
                updated_content.append(line)
                updated_content.append(f'    rule_id::{tenant_name}: {rule_id}\n')
            else:
                updated_content.append(line)
        with open(file_path, 'w', encoding='utf-8') as mdr_file:
            print(updated_content)
            mdr_file.writelines(updated_content)
            logger.info('step_completed', detail=f'Updated MDR File with new ID for tenant {tenant_name}', context=str(rule_id))
