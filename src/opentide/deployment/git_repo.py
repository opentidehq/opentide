import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from opentide.core import registry
from opentide.deployment.git_backend import DulwichRepo, open_repo
from opentide.models.deployment_enums import StatusStrategy
from opentide.registry.discovery import discover_workspace

DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)


def __getattr__(name: str) -> Any:
    """Resolve registry-backed globals on access rather than at import (#536)."""
    if name == "SYSTEMS_CONFIGS_INDEX":
        return registry.Opentide.Configurations.Systems.Index
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


from opentide.core.logging import get_logger
from opentide.deployment.ci import CIEnvironment

logger = get_logger(__name__)


class MissingGitCheckout(Exception):
    """A diff of changed rule files needs a git checkout and none was found."""

    def __init__(self, searched: Path) -> None:
        self.searched = searched
        super().__init__(f"no .git was found from {searched}")


def missing_checkout_message(searched: Path) -> str:
    """The failure for a run that reads changed rule files with no checkout."""
    return (
        "deploy reads the rule files the last commit, push or pull request changed, "
        f"which needs a git checkout; no .git was found from {searched}. "
        "Run inside the repository, or pass --all to read every rule file."
    )


class DiffSource(Enum):
    """Which commits a run's changed rule files come from. Set by the CI context."""

    CHANGE_REQUEST = "the pull or merge request, from its merge base"
    PUSH = "the pushed commit, against its first parent"
    LAST_COMMIT = "the last commit, against its first parent"


def run_diff_source() -> DiffSource:
    """A pull or merge request pipeline reads its request; any other CI run its push.

    Outside CI the run reads the checkout's last commit. Uncommitted edits are
    not in it.
    """
    from opentide.deployment.ci import is_change_request

    environment = CIEnvironment().environment
    if environment is CIEnvironment.CIPlatforms.LocalDebug:
        return DiffSource.LAST_COMMIT
    if is_change_request(environment):
        return DiffSource.CHANGE_REQUEST
    return DiffSource.PUSH


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
    """Rule files a run reads, and the ones in subfolders it skips (#312)."""

    files: tuple[Path, ...] = ()
    nested: tuple[str, ...] = ()


def rules_folder_in_repo() -> str:
    """The rules folder relative to the workspace, spelled as git diff paths are."""
    rule_dir = Path(registry.Opentide.Configurations.Global.Paths.Tide.rule)
    try:
        return rule_dir.relative_to(discover_workspace()).as_posix()
    except ValueError:
        return rule_dir.as_posix()


def local_rule_scope() -> RuleScope:
    """Rule YAML files under the rules folder, split by depth.

    Git does not keep empty folders, so a clone of a repository without rules
    has no rules folder at all: that is an empty catalogue, not an error.
    """
    mdr_path = Path(registry.Opentide.Configurations.Global.Paths.Tide.rule)
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


def modified_rule_scope(source: DiffSource | None = None) -> RuleScope:
    """The rule files the run's diff changed (*source*, else :func:`run_diff_source`)."""
    MDR_PATH = Path(registry.Opentide.Configurations.Global.Paths.Tide.rule)
    changed = diff_calculation(source or run_diff_source())
    top_level, nested_paths = split_changed_rule_paths(changed)
    # The diff path is repo-relative. The file itself lives under the absolute
    # rules folder, and a top-level rule's name is its last path segment.
    mdr_files = [MDR_PATH / Path(path).name for path in top_level]
    logger.info("computed_modified_mdr_files", detail=str(mdr_files))
    return RuleScope(tuple(mdr_files), tuple(nested_paths))


def modified_mdr_files(source: DiffSource | None = None) -> list[Path]:
    return list(modified_rule_scope(source).files)


def changed_rule_scope() -> tuple[RuleScope, DiffSource]:
    """The rule files this run changed, and where the diff came from."""
    source = run_diff_source()
    return modified_rule_scope(source), source


def _local_repository() -> DulwichRepo:
    """The checkout holding the workspace, for a run outside CI."""
    searched = discover_workspace().resolve()
    worktree = _git_worktree(searched)
    if worktree is None:
        raise MissingGitCheckout(searched)
    return open_repo(worktree)


def _production_base(repo: DulwichRepo) -> str | None:
    """HEAD's first parent (``HEAD^1``) when that object is in the checkout.

    The first parent is the default branch before this commit landed, for a
    merge commit, a squash, and a pull request's synthetic merge ref alike.
    The second commit of a date-ordered walk is not: on a merge it is usually
    the merged branch's head, so the rules the merge changed diffed to
    nothing (#546).

    ``None`` means HEAD is the first commit, so a production diff is empty.
    A shallow clone still names the parent and does not contain its object;
    treating that as an empty diff would skip the deploy and exit 0.
    """
    head = repo.head
    if not head.parents:
        return None
    parent = head.parents[0].hexsha
    try:
        repo._repo[parent.encode("ascii")]
    except KeyError:
        raise Exception(f"Could not find git commit {parent}") from None
    return parent


def _merge_ref_base(repo: DulwichRepo, merge_sha: str | None) -> list | None:
    """The merge base of a pull request merge commit's two parents.

    ``refs/pull/<n>/merge`` has the base branch tip as first parent and the
    pull request head as second, so it yields the request's base without the
    head branch existing on origin, as for a pull request from a fork.
    ``None`` when *merge_sha* is not a two-parent commit in the checkout.
    """
    if not merge_sha:
        return None
    try:
        parents = repo.commit(merge_sha).parents
    except Exception:
        return None
    if len(parents) != 2:
        return None
    return repo.merge_base(parents[0].hexsha, parents[1].hexsha)


def _not_a_ci_diff_source(source: DiffSource) -> Exception:
    return Exception(f"{source.name} is not a CI diff source. Use CHANGE_REQUEST or PUSH.")


def _require_origin_ref(repo: DulwichRepo, ref: str) -> None:
    try:
        repo._resolve_sha(ref)
    except KeyError:
        raise Exception(f"Could not find git ref {ref}") from None


def diff_calculation(source: DiffSource) -> list:
    """Repo-relative paths added, renamed or modified by the run's commits.

    *source* is :class:`DiffSource`: a pull or merge request diffs from its
    merge base to its tip, a push from HEAD's first parent (GitLab: the
    previous tip), and a local run from the last commit's first parent.
    Deleted files are left out: there is nothing left to deploy.
    """
    TARGET_CI = CIEnvironment().environment

    if source is DiffSource.LAST_COMMIT or TARGET_CI is CIEnvironment.CIPlatforms.LocalDebug:
        if source is DiffSource.CHANGE_REQUEST:
            raise Exception("A pull or merge request diff needs a CI run")
        repo = _local_repository()
        base = _production_base(repo)
        if base is None:
            return []
        return _changed_paths(repo, repo.commit(base), repo.head)

    repo = TideRepo().repository

    match TARGET_CI:
        case CIEnvironment.CIPlatforms.GitHubActions:
            logger.info("identified_github_actions_as_the_ci_runtime_platform")
            LATEST_COMMIT = os.getenv("GITHUB_SHA")

            if source is DiffSource.PUSH:
                base = _production_base(repo)
                if base is None:
                    return []
                BASE_COMMIT = base

            elif source is DiffSource.CHANGE_REQUEST:
                source_branch = os.getenv("GITHUB_HEAD_REF")
                target_branch = os.getenv("GITHUB_BASE_REF")

                if not source_branch or not target_branch:
                    message = (
                        "Expected to find GITHUB_HEAD_REF and GITHUB_BASE_REF"
                        " | Ensure this is running in a Pull Request pipeline"
                    )
                    logger.critical(
                        "could_not_identify_source_and_target_branch",
                        detail=message,
                    )
                    raise Exception(message)

                repo.remotes.origin.fetch()

                source_branch = source_branch.replace("refs/heads/", "")
                source_branch = "origin/" + source_branch
                target_branch = "origin/" + target_branch
                logger.info(
                    "identified_source_and_target_branch_in_the_pull_request",
                    detail=f"source: {source_branch} -> target: {target_branch}",
                )
                _require_origin_ref(repo, target_branch)
                try:
                    _require_origin_ref(repo, source_branch)
                except Exception:
                    # A fork's branch is not on origin. The pull request's merge
                    # ref, which actions/checkout checks out, has both sides.
                    base_commit = _merge_ref_base(repo, os.getenv("GITHUB_SHA"))
                    if base_commit is None:
                        raise
                else:
                    base_commit = repo.merge_base(target_branch, source_branch)

                if base_commit:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    message = (
                        "You may not have a sufficient Checkout Depth configuration"
                        " | "
                        "If you run very old Pull Requests, this setting may need to be increased, or reopen a PR"
                    )
                    logger.critical("could_not_identify_the_base_of_the_pull_request", detail=message)
                    raise Exception(message)
            else:
                raise _not_a_ci_diff_source(source)

        case CIEnvironment.CIPlatforms.GitlabCI:
            logger.info("identified_gitlab_ci_as_the_ci_runtime_platform")
            LATEST_COMMIT = os.getenv("CI_COMMIT_SHA")

            if source is DiffSource.PUSH:
                BASE_COMMIT = os.getenv("CI_COMMIT_BEFORE_SHA")
                if not BASE_COMMIT or not BASE_COMMIT.strip("0"):
                    # All zeros on a branch's first push, a manual run and a
                    # schedule: there is no previous tip. Diff against HEAD's
                    # first parent, as GitHub and Azure always do.
                    base = _production_base(repo)
                    if base is None:
                        return []
                    BASE_COMMIT = base
            elif source is DiffSource.CHANGE_REQUEST:
                BASE_COMMIT = os.getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
                # Allows the proper base commit calculation for Merged Result pipelines
                if os.getenv("CI_MERGE_REQUEST_EVENT_TYPE") == "merged_result":
                    logger.info("currently_running_a_diff_calculation_for_merge_results")
                    for commit in repo.iter_commits():
                        if commit.hexsha == os.getenv("CI_COMMIT_BEFORE_SHA"):
                            if len(commit.parents) > 1:
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
                logger.critical("illegal_diff_source")
                raise _not_a_ci_diff_source(source)

        case CIEnvironment.CIPlatforms.AzurePipeline:
            logger.info("identified_azure_pipeline_as_the_ci_runtime_platform")
            LATEST_COMMIT = os.getenv("BUILD_SOURCEVERSION")

            if source is DiffSource.PUSH:
                base = _production_base(repo)
                if base is None:
                    return []
                BASE_COMMIT = base

            elif source is DiffSource.CHANGE_REQUEST:
                source_branch = os.getenv("SYSTEM_PULLREQUEST_SOURCEBRANCH")
                target_branch = os.getenv("SYSTEM_PULLREQUEST_TARGETBRANCHNAME")

                if not source_branch or not target_branch:
                    message = (
                        "Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and "
                        "SYSTEM_PULLREQUEST_TARGETBRANCHNAME"
                        " | Ensure this is running in a Pull Request pipeline"
                    )
                    logger.critical(
                        "could_not_identify_source_and_target_branch_using_predefined_azure_pipeline_vari",
                        detail=message,
                    )
                    raise Exception(message)

                repo.remotes.origin.fetch()
                source_branch = source_branch.replace("refs/heads/", "")
                source_branch = "origin/" + source_branch
                target_branch = "origin/" + target_branch
                logger.info(
                    "identified_source_and_target_branch_in_the_pull_request",
                    detail=f"source: {source_branch} -> target: {target_branch}",
                )
                _require_origin_ref(repo, target_branch)
                _require_origin_ref(repo, source_branch)
                base_commit = repo.merge_base(target_branch, source_branch)

                if base_commit:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    message = (
                        "You may not have a sufficient Opentide.Repo.Checkout.Depth configuration"
                        " | "
                        "If you run very old Pull Requests, this setting may need to be increased, or reopen a PR"
                    )
                    logger.critical("could_not_identify_the_base_of_the_pull_request", detail=message)
                    raise Exception(message)

            else:
                logger.critical("illegal_diff_source")
                raise _not_a_ci_diff_source(source)

        case _:
            logger.critical("illegal_ci_environment_detected", detail=str(TARGET_CI))
            raise Exception(f"Unsupported CI environment {TARGET_CI}")

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

    tip_names = {
        CIEnvironment.CIPlatforms.GitHubActions: "GITHUB_SHA",
        CIEnvironment.CIPlatforms.GitlabCI: "CI_COMMIT_SHA",
        CIEnvironment.CIPlatforms.AzurePipeline: "BUILD_SOURCEVERSION",
    }
    if not LATEST_COMMIT:
        raise Exception(f"{tip_names[TARGET_CI]} is required to compute the changed rules")

    return _changed_paths(repo, source_commit, repo.commit(LATEST_COMMIT))


#: The variable naming the commit that triggered the run, per CI platform.
TRIGGER_SHA_VARIABLES = {
    CIEnvironment.CIPlatforms.GitHubActions: "GITHUB_SHA",
    CIEnvironment.CIPlatforms.GitlabCI: "CI_COMMIT_SHA",
    CIEnvironment.CIPlatforms.AzurePipeline: "BUILD_SOURCEVERSION",
}


def _resolve_commit(repo: DulwichRepo, rev: str) -> Any:
    """A full commit SHA, or a branch, ``origin/<branch>`` or ``refs/...`` name."""
    try:
        return repo.commit(rev)
    except Exception:
        pass
    try:
        sha = repo._resolve_sha(rev)
    except KeyError:
        raise Exception(f"Could not find git commit {rev}") from None
    return repo.commit(sha.decode("ascii"))


def _push_baseline(repo: DulwichRepo, environment: Any) -> Any | None:
    """Where the triggering push's diff starts, as the production deploy computes it.

    The deploy reads it from ``HEAD``, which is the triggering commit there. A
    job that checked out a later tip names the triggering commit through the
    CI variable instead: its first parent on GitHub and Azure, and on GitLab
    ``CI_COMMIT_BEFORE_SHA`` unless that is unset or all zeros. ``None`` when
    the triggering commit is the first one, so there is nothing to diff.
    """
    variable = TRIGGER_SHA_VARIABLES.get(environment)
    if variable is None:
        raise Exception(f"Unsupported CI environment {environment}")
    trigger = os.getenv(variable)
    if not trigger:
        raise Exception(f"{variable} is required to compute the changed objects")
    if environment is CIEnvironment.CIPlatforms.GitlabCI:
        before = os.getenv("CI_COMMIT_BEFORE_SHA")
        if before and before.strip("0"):
            return repo.commit(before)
    commit = repo.commit(trigger)
    if not commit.parents:
        return None
    # A shallow clone names the parent without holding it: that fails here.
    return repo.commit(commit.parents[0].hexsha)


def changed_through_head(since: str | None = None) -> list:
    """Paths the push changed, up to the checkout's ``HEAD`` rather than the pushed commit.

    For a job that runs after the production deploy and checks out the
    default branch's tip (#590): the diff starts where the triggering push's
    diff starts (:func:`_push_baseline`) and ends at ``HEAD``, so it holds
    both the push's own changes and the deploy's ``[skip ci]`` write-back,
    which rewrites promoted rules' statuses. In a job whose ``HEAD`` is the
    triggering commit it is the push's diff, as before.

    *since* replaces the baseline with a commit SHA or ref of the caller's
    choosing, and also works outside CI. Deleted files are left out, as in
    :func:`diff_calculation`.
    """
    environment = CIEnvironment().environment
    if environment is CIEnvironment.CIPlatforms.LocalDebug:
        if since is None:
            raise Exception("Outside CI, --since must name the commit to diff from")
        repo = _local_repository()
    else:
        repo = TideRepo().repository
    head = repo.head
    if since is not None:
        base = _resolve_commit(repo, since)
    else:
        base = _push_baseline(repo, environment)
    if base is None:
        return []
    logger.info("changed_through_head_range", detail=f"{base.hexsha} | {head.hexsha}")
    return _changed_paths(repo, base, head)


def _changed_paths(repo: DulwichRepo, source_commit: Any, latest_commit: Any) -> list:
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


def __dir__() -> list[str]:
    return sorted(set(globals()) | {"SYSTEMS_CONFIGS_INDEX"})
