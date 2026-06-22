import pandas as pd
from git.repo import Repo
from Engines.modules.framework import unroll_dot_dict
from Engines.modules.models import (
    TideDefinitionsModels,
    TideModels,
    SystemConfig,
    DeploymentStrategy,
    StatusStrategy,
    TenantDeployment,
    TenantDeploymentModel,
)
from Engines.modules.tide import OpenTide, DetectionPlatforms, ObjectLoader
from Engines.modules.errors import Errors
from Engines.modules.debug import DebugEnvironment
from Engines.modules.environment import DebugHelpers
from Engines.modules.logs import log
import sys
import os
import git
import yaml
import re
from typing import MutableMapping, Sequence
from enum import Enum, auto
from pathlib import Path
from dataclasses import asdict, dataclass


sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))


SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION,
                        StatusStrategy.DISABLEMENT)

from Engines.modules.ci import CIEnvironment

class GitRepository:

    def __init__(self):
        self.repository = self._initialize_repository()
        self.last_commit_details = self._latest_commit_information()
    
    @dataclass
    class LatestCommit:
        message: str
        author: str
        sha: str

    def _initialize_repository(self)->git.Repo:
        TARGET_CI = CIEnvironment().environment
        match TARGET_CI:
            case CIEnvironment.CIPlatforms.GitHubActions:
                log("INFO", "Identified GitHub Actions as the CI Runtime Platform")
                REPO_DIR = os.getenv("GITHUB_WORKSPACE")
            case CIEnvironment.CIPlatforms.GitlabCI:
                log("INFO", "Identified Gitlab CI as the CI Runtime Platform")
                REPO_DIR = os.getenv("CI_PROJECT_DIR")
            case CIEnvironment.CIPlatforms.AzurePipeline:
                log("INFO", "Identified Azure Pipeline as the CI Runtime Platform")
                REPO_DIR = os.getenv("BUILD_SOURCESDIRECTORY")
            case CIEnvironment.CIPlatforms.LocalDebug:
                return None #type: ignore
        log("INFO",
            "Will initialize repository located on",
            str(REPO_DIR))

        return Repo(REPO_DIR)


    def _latest_commit_information(self)->LatestCommit:
        
        if CIEnvironment().environment is CIEnvironment.CIPlatforms.LocalDebug:
            return self.LatestCommit(message = "Sample Commit Message",
                                    author = "Sample Commit Author",
                                    sha = "Sample Commit SHA")
        commit = self.repository.head.commit
        return self.LatestCommit(message = str(commit.message.strip()),
                                 author = str(commit.author.name),
                                 sha = str(commit.hexsha))

def modified_mdr_files(plan: DeploymentStrategy) -> list[Path]:
    MDR_PATH = Path(OpenTide.Configurations.Global.Paths.Tide.mdr)
    MDR_PATH_RAW = OpenTide.Configurations.Global.Paths.Tide._raw["mdr"]
    MDR_PATH_RAW = MDR_PATH_RAW.replace(r"/", r"\/")

    mdr_path_regex = rf"^.*{MDR_PATH_RAW}[^\/]+(\.yaml|\.yml)$"
    mdr_files = [
        mdr.split("/")[-1]
        for mdr in diff_calculation(plan)
        if re.match(mdr_path_regex, mdr)
    ]
    # Extracting only the file name so it can be appended to MDR_PATH
    # which is absolute, and thus more reliable

    mdr_files = [(MDR_PATH / Path(f)) for f in mdr_files]
    log("INFO", "Computed modified MDR Files", str(mdr_files))
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

    repo = TideRepo().repository

    match TARGET_CI:
        case CIEnvironment.CIPlatforms.GitHubActions:
            log("INFO", "Identified GitHub Actions as the CI Runtime Platform")
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
                    log(
                        "FATAL",
                        "Could not identify source and target branch using predefined Azure Pipeline variables",
                        "Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
                        "Ensure this is runnning in a Pull Request pipeline",
                    )
                    raise KeyError

                source_branch = source_branch.replace("refs/heads/", "")
                source_branch = "origin/" + source_branch
                target_branch = "origin/" + target_branch
                log(
                    "INFO",
                    "Identified source and target branch in the pull request",
                    f"source: {source_branch} -> target: {target_branch}",
                )
                base_commit = repo.merge_base(target_branch, source_branch)

                if base_commit[0]:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    log(
                        "FATAL",
                        "Could not identify the base of the Pull Request",
                        "You may not have a sufficient Checkout Depth configuration",
                        "If you run very old Pull Requests, this setting may need to be increased, or reopen a PR",
                    )
                    raise Errors

        case CIEnvironment.CIPlatforms.GitlabCI:
            log("INFO", "Identified Gitlab CI as the CI Runtime Platform")
            LATEST_COMMIT = os.getenv("CI_COMMIT_SHA")

            if plan is DeploymentStrategy.PRODUCTION:
                BASE_COMMIT = os.getenv("CI_COMMIT_BEFORE_SHA")
            elif plan is DeploymentStrategy.STAGING:
                BASE_COMMIT = os.getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
                # Allows the proper base commit calculation for Merged Result pipelines
                if os.getenv("CI_MERGE_REQUEST_EVENT_TYPE") == "merged_result":
                    log(
                        "INFO", "Currently running a diff calculation for merge results"
                    )
                    for commit in repo.iter_commits():
                        if commit.hexsha == os.getenv("CI_COMMIT_BEFORE_SHA"):
                            mr_correct_parent = commit.parents[1]
                            log(
                                "INFO",
                                "Current evaluating commit and found parent",
                                f"{commit.hexsha} | {commit.message}",
                                str(mr_correct_parent),
                            )
                            LATEST_COMMIT = mr_correct_parent
                            break
            else:
                log(
                    "FATAL",
                    f"Illegal Deployment Plan {
                        str(plan)
                    } passed to diff_calculation algorithm",
                )
                raise KeyError

        case CIEnvironment.CIPlatforms.AzurePipeline:
            log("INFO", "Identified Azure Pipeline as the CI Runtime Platform")
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
                target_branch = os.getenv(
                    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME")

                if not source_branch or not target_branch:
                    log(
                        "FATAL",
                        "Could not identify source and target branch using predefined Azure Pipeline variables",
                        "Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
                        "Ensure this is runnning in a Pull Request pipeline",
                    )
                    raise KeyError

                source_branch = source_branch.replace("refs/heads/", "")
                source_branch = "origin/" + source_branch
                target_branch = "origin/" + target_branch
                log(
                    "INFO",
                    "Identified source and target branch in the pull request",
                    f"source: {source_branch} -> target: {target_branch}",
                )
                base_commit = repo.merge_base(target_branch, source_branch)

                if base_commit[0]:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    log(
                        "FATAL",
                        "Could not identify the base of the Pull Request",
                        "You may not have a sufficient OpenTide.Repo.Checkout.Depth configuration",
                        "If you run very old Pull Requests, this setting may need to be increased, or reopen a PR",
                    )
                    raise Errors

            else:
                log(
                    "FATAL",
                    f"Illegal Deployment Plan {
                        str(plan)
                    } passed to diff_calculation algorithm",
                )
                raise KeyError

        case _:
            log("FATAL", "Illegal CI Environment detected", str(TARGET_CI))

            raise Exception

    log(
        "INFO",
        "Setting source and target commit for the diff calculation to",
        f"{BASE_COMMIT} | {LATEST_COMMIT}",
    )

    source_commit = None
    try:
        source_commit = repo.commit(BASE_COMMIT)
    except Exception:
        log(
            "INFO",
            "Could not find source commit in current branch, trying iter_commits method",
        )
        remote_refs = repo.remote().refs

        for refs in remote_refs:
            log("INFO", refs.name)

        for commit in repo.iter_commits("origin/main"):
            log("INFO", "Currently Evaluating", f"{commit.message}")
            if commit.hexsha == BASE_COMMIT:
                source_commit = commit
                log(
                    "SUCCESS",
                    "Found source commit",
                    f"{commit.hexsha} | {commit.message}",
                )
                break

    if not source_commit:
        log("FATAL", "No Source Commit could be identified")
        raise Exception("No Source Commit Found")

    latest_commit = repo.commit(LATEST_COMMIT)
    diff = source_commit.diff(latest_commit)

    log(
        "INFO",
        "Preliminary diff calculation completed, returned with",
        ", ".join([f.b_path for f in diff]),
    )

    # Computing diff for added/renamed paths and modified files.
    # Deleted files are explicitely excluded to avoid attempting to deploy
    # something that is not material anymore.
    added_files = [f.b_path for f in diff.iter_change_type("A")]
    renamed_files = [f.b_path for f in diff.iter_change_type("R")]
    modified_files = [f.b_path for f in diff.iter_change_type("M")]

    scope = added_files + renamed_files + modified_files
    scope = list(
        set(scope)
    )  # De-duplicate - may happen if file modified and renamed, for example
    log("INFO", "Computed diff scope", ", ".join(scope))

    return scope


# Legacy alias
TideRepo = GitRepository

