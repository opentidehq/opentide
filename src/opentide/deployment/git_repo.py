import json
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from opentide.core import registry
from opentide.core.logging import get_logger
from opentide.deployment.ci import CIEnvironment
from opentide.deployment.git_backend import CommitInfo, DulwichRepo, open_repo
from opentide.models.deployment_enums import StatusStrategy
from opentide.registry.discovery import discover_workspace

DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)


def __getattr__(name: str) -> Any:
    """Resolve registry-backed globals on access rather than at import (#536)."""
    if name == "SYSTEMS_CONFIGS_INDEX":
        return registry.Opentide.Configurations.Systems.Index
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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

    CHANGE_REQUEST = "the pull or merge request, against its target branch"
    PUSH = "the pushed commits, against the branch's previous tip"
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
    def __init__(self) -> None:
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
                return None
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
        # Only a local run has no repository (see ``_initialize_repository``).
        if self.repository is None:
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
    logger.info("computed_modified_rule_files", detail=str(mdr_files))
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


def _has_commit(repo: DulwichRepo, sha: str) -> bool:
    """Whether the commit object *sha* is in the checkout (a shallow clone may lack it)."""
    try:
        repo.commit(sha)
    except Exception:
        return False
    return True


def _merge_first_parent(
    repo: DulwichRepo, merge_sha: str | None, *, head: str | None = None
) -> str | None:
    """The first parent of the merge commit a pull or merge request run builds.

    GitHub (``refs/pull/<n>/merge``), Azure Pipelines and GitLab merged
    results pipelines build a commit that merges the request into the target
    branch's tip, which is its first parent. Diffing from that parent yields
    the request's own changes. Diffing from the merge base to the merge commit
    also listed every rule the target branch changed since the request
    branched off, and the run deployed, validated and attributed those to the
    request.

    ``None`` when *merge_sha* is not a two-parent commit whose first parent is
    in the checkout, or when *head* is given and is not its second parent.
    """
    if not merge_sha:
        return None
    try:
        parents = repo.commit(merge_sha).parents
    except Exception:
        return None
    if len(parents) != 2:
        return None
    first, second = parents
    if head and second.hexsha != head:
        return None
    if not _has_commit(repo, first.hexsha):
        return None
    return first.hexsha


def _github_push_before(repo: DulwichRepo) -> str | None:
    """The branch tip before this push, from the push event's ``before``.

    One push can land several commits (a rebase merge, a direct push of a
    series), and ``HEAD^1`` covers only the last one. ``None`` when the event
    has no usable ``before``: not a push, the branch's first push (all
    zeros), or a commit the checkout does not have.
    """
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    before = event.get("before") if isinstance(event, dict) else None
    if not isinstance(before, str) or not before.strip("0"):
        return None
    if not _has_commit(repo, before):
        logger.info("push_before_not_in_checkout", before=before)
        return None
    return before


def _github_event_request_shas(repo: DulwichRepo) -> tuple[str, str] | None:
    """The pull request's base and head commits, from the event payload.

    ``pull_request_target`` runs on the base branch, and a fork's head branch
    is not on ``origin``, so neither ``GITHUB_SHA`` nor the branch names lead
    to the request's commits. ``None`` when the payload lacks them or the
    checkout does not hold both.
    """
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    request = event.get("pull_request") if isinstance(event, dict) else None
    if not isinstance(request, dict):
        return None
    base, head = ((request.get(side) or {}).get("sha") for side in ("base", "head"))
    if not isinstance(base, str) or not isinstance(head, str):
        return None
    if not (_has_commit(repo, base) and _has_commit(repo, head)):
        logger.info("pull_request_shas_not_in_checkout", base=base, head=head)
        return None
    return base, head


def _origin_sha(repo: DulwichRepo, ref: str) -> str:
    """The commit *ref* (``origin/<branch>``) names."""
    return repo._resolve_sha(ref).decode("ascii")


def _not_a_ci_diff_source(source: DiffSource) -> Exception:
    return Exception(f"{source.name} is not a CI diff source. Use CHANGE_REQUEST or PUSH.")


def _require_origin_ref(repo: DulwichRepo, ref: str) -> None:
    try:
        repo._resolve_sha(ref)
    except KeyError:
        raise Exception(f"Could not find git ref {ref}") from None


def diff_calculation(source: DiffSource) -> list[str]:
    """Repo-relative paths added, renamed or modified by the run's commits.

    *source* is :class:`DiffSource`. A pull or merge request run that builds
    the request merged into its target branch diffs that merge commit from
    its first parent, the target's tip; one that builds the request's head
    diffs it from the merge base. A push diffs from the branch's previous tip
    (GitHub: the event's ``before``; GitLab: ``CI_COMMIT_BEFORE_SHA``), else
    from HEAD's first parent, as on Azure. A local run diffs the last commit
    from its first parent. Deleted files are left out: there is nothing left
    to deploy.
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
    if repo is None:
        # Only a local run has no repository, and it returned above.
        raise MissingGitCheckout(discover_workspace())

    match TARGET_CI:
        case CIEnvironment.CIPlatforms.GitHubActions:
            logger.info("identified_github_actions_as_the_ci_runtime_platform")
            LATEST_COMMIT = os.getenv("GITHUB_SHA")

            if source is DiffSource.PUSH:
                before = _github_push_before(repo)
                if before is not None:
                    logger.info("push_diff_base", base=before, source="push event before")
                    BASE_COMMIT = before
                else:
                    base = _production_base(repo)
                    if base is None:
                        return []
                    logger.info("push_diff_base", base=base, source="first parent of HEAD")
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

                # ``pull_request_target`` runs on the base branch: GITHUB_SHA is
                # that branch's tip, which may be any merge, not this request's.
                # The event payload names its commits, which a fork's branch
                # on ``origin`` cannot.
                merge_parent = None
                request_shas = None
                if os.getenv("GITHUB_EVENT_NAME") != "pull_request_target":
                    merge_parent = _merge_first_parent(repo, LATEST_COMMIT)
                else:
                    request_shas = _github_event_request_shas(repo)
                request_base = repo.merge_base(*request_shas) if request_shas else []

                if merge_parent is not None:
                    BASE_COMMIT = merge_parent
                elif request_shas and request_base:
                    BASE_COMMIT = request_base[0].hexsha
                    LATEST_COMMIT = request_shas[1]
                    logger.info("pull_request_diff_from_event", base=BASE_COMMIT)
                else:
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
                        LATEST_COMMIT = _origin_sha(repo, source_branch)
                    else:
                        message = (
                            "You may not have a sufficient Checkout Depth configuration | "
                            "If you run very old Pull Requests, this setting may need to be "
                            "increased, or reopen a PR"
                        )
                        logger.critical(
                            "could_not_identify_the_base_of_the_pull_request", detail=message
                        )
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
                # Merged results and merge train pipelines build a commit that
                # merges the request into the target branch; diff it from the
                # target side, as for GitHub and Azure.
                if os.getenv("CI_MERGE_REQUEST_EVENT_TYPE") in ("merged_result", "merge_train"):
                    logger.info("currently_running_a_diff_calculation_for_merge_results")
                    source_head = os.getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA") or None
                    merge_parent = _merge_first_parent(repo, LATEST_COMMIT, head=source_head)
                    if merge_parent is not None:
                        BASE_COMMIT = merge_parent
                    elif source_head:
                        LATEST_COMMIT = source_head
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

                merge_parent = _merge_first_parent(
                    repo,
                    LATEST_COMMIT,
                    head=os.getenv("SYSTEM_PULLREQUEST_SOURCECOMMITID") or None,
                )
                if merge_parent is not None:
                    BASE_COMMIT = merge_parent
                else:
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
                        LATEST_COMMIT = _origin_sha(repo, source_branch)
                    else:
                        message = (
                            "You may not have a sufficient Opentide.Repo.Checkout.Depth"
                            " configuration | "
                            "If you run very old Pull Requests, this setting may need to be "
                            "increased, or reopen a PR"
                        )
                        logger.critical(
                            "could_not_identify_the_base_of_the_pull_request", detail=message
                        )
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

    source_commit: CommitInfo | None = None
    try:
        if BASE_COMMIT:
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


def _changed_paths(
    repo: DulwichRepo, source_commit: CommitInfo, latest_commit: CommitInfo
) -> list[str]:
    diff = source_commit.diff(latest_commit)

    logger.info(
        "preliminary_diff_calculation_completed_returned_with",
        detail=", ".join([f.b_path for f in diff if f.b_path]),
    )

    # Computing diff for added/renamed paths and modified files.
    # Deleted files are explicitely excluded to avoid attempting to deploy
    # something that is not material anymore. An added, renamed or modified
    # entry always has a path.
    added_files = [f.b_path for f in diff.iter_change_type("A") if f.b_path]
    renamed_files = [f.b_path for f in diff.iter_change_type("R") if f.b_path]
    modified_files = [f.b_path for f in diff.iter_change_type("M") if f.b_path]

    scope = added_files + renamed_files + modified_files
    scope = list(set(scope))  # De-duplicate - may happen if file modified and renamed, for example
    logger.info("computed_diff_scope", detail=", ".join(scope))

    return scope


# Legacy alias
TideRepo = GitRepository


def __dir__() -> list[str]:
    return sorted(set(globals()) | {"SYSTEMS_CONFIGS_INDEX"})
