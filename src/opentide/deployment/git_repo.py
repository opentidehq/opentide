import os
import re
from dataclasses import dataclass
from pathlib import Path

from opentide.core.errors import Errors
from opentide.core.registry import OpenTide
from opentide.deployment.git_backend import DulwichRepo, open_repo
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy
from opentide.registry.discovery import discover_workspace

SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)

from opentide.core.logging import get_logger
from opentide.deployment.ci import CIEnvironment

logger = get_logger(__name__)


class MissingGitCheckout(Exception):
    """A CI diff plan needs a git checkout and none was found."""

    def __init__(self, searched: Path) -> None:
        self.searched = searched
        super().__init__(f"no .git was found from {searched}")


def missing_checkout_message(plan: str, searched: Path) -> str:
    """The deploy failure for a STAGING or PRODUCTION plan with no checkout."""
    return (
        f"deploy --plan {plan} needs a git checkout to compute changed rules; "
        f"no .git was found from {searched}. "
        "Run inside the repository, or use --plan FULL."
    )


def _git_worktree(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        git_path = candidate / ".git"
        if git_path.is_dir() or git_path.is_file():
            return candidate
    return None


class GitRepository:
    def __init__(self):
        self.repository = self._initialize_repository()
        self.last_commit_details = self._latest_commit_information()

    @dataclass
    class LatestCommit:
        message: str
        author: str
        sha: str

    def _initialize_repository(self) -> DulwichRepo | None:
        TARGET_CI = CIEnvironment().environment
        match TARGET_CI:
            case CIEnvironment.CIPlatforms.GitHubActions:
                logger.info("identified_github_actions_as_the_ci_runtime_platform")
                raw = os.getenv("GITHUB_WORKSPACE")
            case CIEnvironment.CIPlatforms.GitlabCI:
                logger.info("identified_gitlab_ci_as_the_ci_runtime_platform")
                raw = os.getenv("CI_PROJECT_DIR")
            case CIEnvironment.CIPlatforms.AzurePipeline:
                logger.info("identified_azure_pipeline_as_the_ci_runtime_platform")
                raw = os.getenv("BUILD_SOURCESDIRECTORY")
            case CIEnvironment.CIPlatforms.LocalDebug:
                return None  # type: ignore
            case _:
                raw = None
        searched = Path(raw).expanduser() if raw else Path.cwd()
        if not searched.is_absolute():
            searched = Path.cwd() / searched
        searched = searched.resolve()
        if _git_worktree(searched) is None:
            raise MissingGitCheckout(searched)
        logger.info("will_initialize_repository_located_on", detail=str(searched))
        return open_repo(searched)

    def _latest_commit_information(self) -> LatestCommit:

        if CIEnvironment().environment is CIEnvironment.CIPlatforms.LocalDebug:
            return self.LatestCommit(
                message="Sample Commit Message",
                author="Sample Commit Author",
                sha="Sample Commit SHA",
            )
        commit = self.repository.head
        return self.LatestCommit(
            message=str(commit.message.strip()),
            author=str(commit.author.name),
            sha=str(commit.hexsha),
        )


RULE_SUFFIXES = (".yaml", ".yml")


@dataclass(frozen=True)
class RuleScope:
    """Rule files a plan reads, and the ones in subfolders it skips (#312)."""

    files: tuple[Path, ...] = ()
    nested: tuple[str, ...] = ()


def rules_folder_in_repo() -> str:
    """The rules folder relative to the workspace, spelled as git diff paths are."""
    rule_dir = Path(OpenTide.Configurations.Global.Paths.Tide.rule)
    try:
        return rule_dir.relative_to(discover_workspace()).as_posix()
    except ValueError:
        return rule_dir.as_posix()


def local_rule_scope() -> RuleScope:
    """Rule YAML files under the rules folder, split by depth.

    Git does not keep empty folders, so a clone of a repository without rules
    has no rules folder at all: that is an empty catalogue, not an error.
    """
    mdr_path = Path(OpenTide.Configurations.Global.Paths.Tide.rule)
    if not mdr_path.is_dir():
        logger.info("rule_folder_not_found", path=str(mdr_path))
        return RuleScope()
    folder = rules_folder_in_repo()
    files: list[Path] = []
    nested: list[str] = []
    for path in sorted(mdr_path.rglob("*")):
        if not path.is_file() or path.suffix not in RULE_SUFFIXES:
            continue
        if path.parent == mdr_path:
            files.append(path)
        else:
            nested.append(f"{folder}/{path.relative_to(mdr_path).as_posix()}")
    return RuleScope(tuple(files), tuple(nested))


def local_rule_files() -> list[Path]:
    """Rule YAML files directly under the rules folder."""
    return list(local_rule_scope().files)


def split_changed_rule_paths(changed: list[str]) -> tuple[list[str], list[str]]:
    """Split a git diff into top-level rule files and rule files in subfolders.

    Diff entries are repo-relative (``objects/rules/rule.yaml``) or absolute.
    The configured rules folder is absolute, so both patterns use the
    repo-relative folder (#318). A file under ``objects/rules/<subfolder>/``
    stays in the second list.
    """
    folder = re.escape(rules_folder_in_repo().strip("/"))
    top_level = re.compile(rf"(?:^|/){folder}/[^/]+\.(?:yaml|yml)$")
    nested = re.compile(rf"(?:^|/){folder}/.+/[^/]+\.(?:yaml|yml)$")
    top_paths = [path for path in changed if path and top_level.search(path)]
    nested_paths = sorted(path for path in changed if path and nested.search(path))
    return top_paths, nested_paths


def modified_rule_scope(plan: DeploymentStrategy) -> RuleScope:
    """The local rule files, or in CI the rule files the git diff changed."""
    MDR_PATH = Path(OpenTide.Configurations.Global.Paths.Tide.rule)
    if CIEnvironment().environment is CIEnvironment.CIPlatforms.LocalDebug:
        scope = local_rule_scope()
        logger.info("computed_modified_mdr_files", detail=str(list(scope.files)))
        return scope

    changed = diff_calculation(plan)
    top_level, nested_paths = split_changed_rule_paths(changed)
    # The diff path is repo-relative. The file itself lives under the absolute
    # rules folder, and a top-level rule's name is its last path segment.
    mdr_files = [MDR_PATH / Path(path).name for path in top_level]
    logger.info("computed_modified_mdr_files", detail=str(mdr_files))
    return RuleScope(tuple(mdr_files), tuple(nested_paths))


def modified_mdr_files(plan: DeploymentStrategy) -> list[Path]:
    return list(modified_rule_scope(plan).files)


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

    if TARGET_CI is CIEnvironment.CIPlatforms.LocalDebug:
        logger.info(
            "local_debug_using_full_rule_tree",
            detail="Git diff is unavailable outside CI; compiling from the local rules folder",
        )
        raw = OpenTide.Configurations.Global.Paths.Tide._raw["rule"]
        # Repo-relative paths so modified_mdr_files' regex still matches.
        return [str(Path(raw) / path.name) for path in local_rule_files()]

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
                            LATEST_COMMIT = mr_correct_parent.hexsha
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
        try:
            remote_refs = repo.remote().refs

            for refs in remote_refs:
                logger.info("info", detail=refs.name)

            for commit in repo.iter_commits("origin/main"):
                logger.info("currently_evaluating", detail=f"{commit.message}")
                if commit.hexsha == BASE_COMMIT:
                    source_commit = commit
                    logger.info("found_source_commit", detail=f"{commit.hexsha} | {commit.message}")
                    break
        except Exception:
            logger.info("could_not_walk_origin_main_for_the_source_commit")

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
