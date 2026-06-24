import os
import re
from dataclasses import dataclass
from pathlib import Path

from git.repo import Repo

from opentide.core.errors import Errors
from opentide.core.registry import OpenTide
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy

SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)

from opentide.core.logging import get_logger
from opentide.deployment.ci import CIEnvironment

logger = get_logger(__name__)


class GitRepository:
    def __init__(self):
        self.repository = self._initialize_repository()
        self.last_commit_details = self._latest_commit_information()

    @dataclass
    class LatestCommit:
        message: str
        author: str
        sha: str

    def _initialize_repository(self) -> Repo:
        TARGET_CI = CIEnvironment().environment
        match TARGET_CI:
            case CIEnvironment.CIPlatforms.GitHubActions:
                logger.info("identified_github_actions_as_the_ci_runtime_platform")
                REPO_DIR = os.getenv("GITHUB_WORKSPACE")
            case CIEnvironment.CIPlatforms.GitlabCI:
                logger.info("identified_gitlab_ci_as_the_ci_runtime_platform")
                REPO_DIR = os.getenv("CI_PROJECT_DIR")
            case CIEnvironment.CIPlatforms.AzurePipeline:
                logger.info("identified_azure_pipeline_as_the_ci_runtime_platform")
                REPO_DIR = os.getenv("BUILD_SOURCESDIRECTORY")
            case CIEnvironment.CIPlatforms.LocalDebug:
                return None  # type: ignore
        logger.info("will_initialize_repository_located_on", detail=str(REPO_DIR))

        return Repo(REPO_DIR)

    def _latest_commit_information(self) -> LatestCommit:

        if CIEnvironment().environment is CIEnvironment.CIPlatforms.LocalDebug:
            return self.LatestCommit(
                message="Sample Commit Message",
                author="Sample Commit Author",
                sha="Sample Commit SHA",
            )
        commit = self.repository.head.commit
        return self.LatestCommit(
            message=str(commit.message.strip()),
            author=str(commit.author.name),
            sha=str(commit.hexsha),
        )


def modified_mdr_files(plan: DeploymentStrategy) -> list[Path]:
    MDR_PATH = Path(OpenTide.Configurations.Global.Paths.Tide.rule)
    MDR_PATH_RAW = OpenTide.Configurations.Global.Paths.Tide._raw["rule"]
    MDR_PATH_RAW = MDR_PATH_RAW.replace(r"/", r"\/")

    mdr_path_regex = rf"^.*{MDR_PATH_RAW}[^\/]+(\.yaml|\.yml)$"
    mdr_files = [
        mdr.split("/")[-1] for mdr in diff_calculation(plan) if re.match(mdr_path_regex, mdr)
    ]
    # Extracting only the file name so it can be appended to MDR_PATH
    # which is absolute, and thus more reliable

    mdr_files = [(MDR_PATH / Path(f)) for f in mdr_files]
    logger.info("computed_modified_mdr_files", detail=str(mdr_files))
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
    TARGET_CI = CIEnvironment().environment

    repo = TideRepo().repository

    match TARGET_CI:
        case CIEnvironment.CIPlatforms.GitHubActions:
            logger.info("identified_github_actions_as_the_ci_runtime_platform")
            LATEST_COMMIT = os.getenv("GITHUB_SHA")

            if plan is DeploymentStrategy.PRODUCTION:
                commits = list(repo.iter_commits("HEAD", max_count=2))
                if len(commits) > 1:
                    BASE_COMMIT = commits[1].hexsha
                else:
                    return []

            elif plan is DeploymentStrategy.STAGING:
                repo.remotes.origin.fetch()
                source_branch = os.getenv("GITHUB_HEAD_REF")
                target_branch = os.getenv("GITHUB_BASE_REF")

                if not source_branch or not target_branch:
                    logger.critical(
                        "could_not_identify_source_and_target_branch_using_predefined_azure_pipeline_vari",
                        detail="Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME"
                        + " | "
                        + "Ensure this is runnning in a Pull Request pipeline",
                    )
                    raise KeyError

                source_branch = source_branch.replace("refs/heads/", "")
                source_branch = "origin/" + source_branch
                target_branch = "origin/" + target_branch
                logger.info(
                    "identified_source_and_target_branch_in_the_pull_request",
                    detail=f"source: {source_branch} -> target: {target_branch}",
                )
                base_commit = repo.merge_base(target_branch, source_branch)

                if base_commit[0]:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    logger.critical(
                        "could_not_identify_the_base_of_the_pull_request",
                        detail="You may not have a sufficient Checkout Depth configuration"
                        + " | "
                        + "If you run very old Pull Requests, this setting may need to be increased, or reopen a PR",
                    )
                    raise Errors

        case CIEnvironment.CIPlatforms.GitlabCI:
            logger.info("identified_gitlab_ci_as_the_ci_runtime_platform")
            LATEST_COMMIT = os.getenv("CI_COMMIT_SHA")

            if plan is DeploymentStrategy.PRODUCTION:
                BASE_COMMIT = os.getenv("CI_COMMIT_BEFORE_SHA")
            elif plan is DeploymentStrategy.STAGING:
                BASE_COMMIT = os.getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
                # Allows the proper base commit calculation for Merged Result pipelines
                if os.getenv("CI_MERGE_REQUEST_EVENT_TYPE") == "merged_result":
                    logger.info("currently_running_a_diff_calculation_for_merge_results")
                    for commit in repo.iter_commits():
                        if commit.hexsha == os.getenv("CI_COMMIT_BEFORE_SHA"):
                            mr_correct_parent = commit.parents[1]
                            logger.info(
                                "current_evaluating_commit_and_found_parent",
                                detail=str(f"{commit.hexsha} | {commit.message}")
                                + " | "
                                + str(str(mr_correct_parent)),
                            )
                            LATEST_COMMIT = mr_correct_parent
                            break
            else:
                logger.critical("illegal_deployment_plan")
                raise KeyError

        case CIEnvironment.CIPlatforms.AzurePipeline:
            logger.info("identified_azure_pipeline_as_the_ci_runtime_platform")
            LATEST_COMMIT = os.getenv("BUILD_SOURCEVERSION")

            if plan is DeploymentStrategy.PRODUCTION:
                commits = list(repo.iter_commits("HEAD", max_count=2))
                if len(commits) > 1:
                    BASE_COMMIT = commits[1].hexsha
                else:
                    return []

            elif plan is DeploymentStrategy.STAGING:
                repo.remotes.origin.fetch()
                source_branch = os.getenv("SYSTEM_PULLREQUEST_SOURCEBRANCH")
                target_branch = os.getenv("SYSTEM_PULLREQUEST_TARGETBRANCHNAME")

                if not source_branch or not target_branch:
                    logger.critical(
                        "could_not_identify_source_and_target_branch_using_predefined_azure_pipeline_vari",
                        detail="Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME"
                        + " | "
                        + "Ensure this is runnning in a Pull Request pipeline",
                    )
                    raise KeyError

                source_branch = source_branch.replace("refs/heads/", "")
                source_branch = "origin/" + source_branch
                target_branch = "origin/" + target_branch
                logger.info(
                    "identified_source_and_target_branch_in_the_pull_request",
                    detail=f"source: {source_branch} -> target: {target_branch}",
                )
                base_commit = repo.merge_base(target_branch, source_branch)

                if base_commit[0]:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    logger.critical(
                        "could_not_identify_the_base_of_the_pull_request",
                        detail="You may not have a sufficient OpenTide.Repo.Checkout.Depth configuration"
                        + " | "
                        + "If you run very old Pull Requests, this setting may need to be increased, or reopen a PR",
                    )
                    raise Errors

            else:
                logger.critical("illegal_deployment_plan")
                raise KeyError

        case _:
            logger.critical("illegal_ci_environment_detected", detail=str(TARGET_CI))

            raise Exception

    logger.info(
        "setting_source_and_target_commit_for_the_diff_calculation_to",
        detail=f"{BASE_COMMIT} | {LATEST_COMMIT}",
    )

    source_commit = None
    try:
        source_commit = repo.commit(BASE_COMMIT)
    except Exception:
        logger.info("could_not_find_source_commit_in_current_branch_trying_iter_commits_method")
        remote_refs = repo.remote().refs

        for refs in remote_refs:
            logger.info("info", detail=refs.name)

        for commit in repo.iter_commits("origin/main"):
            logger.info("currently_evaluating", detail=f"{commit.message}")
            if commit.hexsha == BASE_COMMIT:
                source_commit = commit
                logger.info("found_source_commit", detail=f"{commit.hexsha} | {commit.message}")
                break

    if not source_commit:
        logger.critical("no_source_commit_could_be_identified")
        raise Exception("No Source Commit Found")

    latest_commit = repo.commit(LATEST_COMMIT)
    diff = source_commit.diff(latest_commit)

    logger.info(
        "preliminary_diff_calculation_completed_returned_with",
        detail=", ".join([f.b_path for f in diff]),
    )

    # Computing diff for added/renamed paths and modified files.
    # Deleted files are explicitely excluded to avoid attempting to deploy
    # something that is not material anymore.
    added_files = [f.b_path for f in diff.iter_change_type("A")]
    renamed_files = [f.b_path for f in diff.iter_change_type("R")]
    modified_files = [f.b_path for f in diff.iter_change_type("M")]

    scope = added_files + renamed_files + modified_files
    scope = list(set(scope))  # De-duplicate - may happen if file modified and renamed, for example
    logger.info("computed_diff_scope", detail=", ".join(scope))

    return scope


# Legacy alias
TideRepo = GitRepository
