"""Which commits a CI run diffs: a request's own changes, a push's every commit."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from opentide.deployment.git_repo import DiffSource, diff_calculation

#: Every variable that selects a CI provider, an event or a diff base.
_CI_ENV = (
    "CI",
    "CI_PROJECT_DIR",
    "CI_COMMIT_SHA",
    "CI_COMMIT_BEFORE_SHA",
    "CI_PIPELINE_SOURCE",
    "CI_MERGE_REQUEST_DIFF_BASE_SHA",
    "CI_MERGE_REQUEST_EVENT_TYPE",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA",
    "GITHUB_ACTIONS",
    "GITHUB_WORKSPACE",
    "GITHUB_SHA",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "TF_BUILD",
    "BUILD_REASON",
    "BUILD_SOURCESDIRECTORY",
    "BUILD_SOURCEVERSION",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
    "SYSTEM_PULLREQUEST_SOURCECOMMITID",
)


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _commit_rule(repo: Path, name: str, body: str, message: str) -> str:
    path = repo / "objects" / "rules" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture(autouse=True)
def _clean_ci_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No provider variables from the runner, and a git identity of our own."""
    for name in _CI_ENV:
        monkeypatch.delenv(name, raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "dev")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "dev@example.test")


@dataclass(frozen=True)
class Request:
    """A pull request checkout: ``ci`` holds the merge of ``feature`` into ``main``."""

    ci: Path
    merge: str
    feature: str
    merge_base: str


@pytest.fixture
def request_checkout(tmp_path: Path) -> Iterator[Request]:
    """``feature`` changes b.yaml; ``main`` changes c.yaml after ``feature`` branched off."""
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    _git(work, "checkout", "-q", "-b", "main")
    for name in ("a.yaml", "b.yaml", "c.yaml"):
        (work / "objects" / "rules").mkdir(parents=True, exist_ok=True)
        (work / "objects" / "rules" / name).write_text(f"name: {name}\n", encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "catalogue")
    merge_base = _git(work, "rev-parse", "HEAD")
    _git(work, "push", "-q", "origin", "main")
    _git(work, "checkout", "-q", "-b", "feature")
    feature = _commit_rule(work, "b.yaml", "name: b2\n", "request changes b")
    _git(work, "push", "-q", "origin", "feature")
    _git(work, "checkout", "-q", "main")
    _commit_rule(work, "c.yaml", "name: c2\n", "main changes c after the branch point")
    _git(work, "push", "-q", "origin", "main")

    # What actions/checkout and Azure check out for a pull request: a merge
    # of the request into the target branch's tip.
    ci = tmp_path / "ci"
    _git(tmp_path, "clone", "-q", str(origin), str(ci))
    _git(ci, "checkout", "-q", "--detach", "origin/main")
    _git(ci, "merge", "-q", "--no-ff", "-m", "Merge feature into main", "origin/feature")
    yield Request(ci, _git(ci, "rev-parse", "HEAD"), feature, merge_base)


def _github_request(monkeypatch: pytest.MonkeyPatch, workspace: Path, sha: str, event: str) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.setenv("GITHUB_SHA", sha)
    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")


def test_github_pull_request_diffs_the_merge_from_the_target_tip(
    request_checkout: Request, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The diff ran from the merge base to the merge commit.

    It listed c.yaml, which only the target branch changed after the request
    branched off, so a pull request run deployed and validated it as its own.
    """
    _github_request(monkeypatch, request_checkout.ci, request_checkout.merge, "pull_request")

    assert diff_calculation(DiffSource.CHANGE_REQUEST) == ["objects/rules/b.yaml"]


def test_github_pull_request_on_the_head_commit_diffs_from_the_merge_base(
    request_checkout: Request, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git(request_checkout.ci, "checkout", "-q", "--detach", request_checkout.feature)
    _github_request(monkeypatch, request_checkout.ci, request_checkout.feature, "pull_request")

    assert diff_calculation(DiffSource.CHANGE_REQUEST) == ["objects/rules/b.yaml"]


def test_github_pull_request_target_diffs_the_request_head(
    request_checkout: Request, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``pull_request_target`` sets GITHUB_SHA to the base branch's tip.

    The diff ended there, so it held the base branch's changes since the
    branch point and none of the request's. A base tip that is itself a merge
    must not be read as the request's merge commit either.
    """
    ci = request_checkout.ci
    _git(ci, "checkout", "-q", "-b", "other", "origin/main~1")
    _commit_rule(ci, "a.yaml", "name: a2\n", "another request changes a")
    _git(ci, "checkout", "-q", "--detach", "origin/main")
    _git(ci, "merge", "-q", "--no-ff", "-m", "Merge other into main", "other")
    base_tip = _git(ci, "rev-parse", "HEAD")
    _git(ci, "checkout", "-q", "--detach", request_checkout.feature)
    _github_request(monkeypatch, ci, base_tip, "pull_request_target")

    assert diff_calculation(DiffSource.CHANGE_REQUEST) == ["objects/rules/b.yaml"]


def test_github_pull_request_target_from_a_fork_diffs_the_event_commits(
    request_checkout: Request, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A fork's head branch is not on ``origin``.

    The run looked for ``origin/<head branch>`` and failed with "Could not find
    git ref"; the event payload names the base and head commits instead.
    """
    ci = request_checkout.ci
    _git(ci, "checkout", "-q", "--detach", request_checkout.feature)
    _git(ci, "update-ref", "-d", "refs/remotes/origin/feature")
    base_tip = _git(ci, "rev-parse", "origin/main")
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {"pull_request": {"base": {"sha": base_tip}, "head": {"sha": request_checkout.feature}}}
        ),
        encoding="utf-8",
    )
    _github_request(monkeypatch, ci, base_tip, "pull_request_target")
    monkeypatch.setenv("GITHUB_HEAD_REF", "fork-feature")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))

    assert diff_calculation(DiffSource.CHANGE_REQUEST) == ["objects/rules/b.yaml"]


@pytest.mark.parametrize("source_commit", [True, False], ids=["source-commit-id", "no-commit-id"])
def test_azure_pull_request_diffs_the_merge_from_the_target_tip(
    request_checkout: Request, monkeypatch: pytest.MonkeyPatch, source_commit: bool
) -> None:
    """BUILD_SOURCEVERSION is the merge commit on a pull request build, as on GitHub."""
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("BUILD_REASON", "PullRequest")
    monkeypatch.setenv("BUILD_SOURCESDIRECTORY", str(request_checkout.ci))
    monkeypatch.setenv("BUILD_SOURCEVERSION", request_checkout.merge)
    monkeypatch.setenv("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feature")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_TARGETBRANCHNAME", "main")
    if source_commit:
        monkeypatch.setenv("SYSTEM_PULLREQUEST_SOURCECOMMITID", request_checkout.feature)

    assert diff_calculation(DiffSource.CHANGE_REQUEST) == ["objects/rules/b.yaml"]


def test_azure_pull_request_ignores_a_merge_that_is_not_the_requests(
    request_checkout: Request, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A source branch that merged the target in is not the build's merge commit."""
    ci = request_checkout.ci
    _git(ci, "checkout", "-q", "-b", "feature", "origin/feature")
    _git(ci, "merge", "-q", "--no-ff", "-m", "Merge main into feature", "origin/main")
    head = _git(ci, "rev-parse", "HEAD")
    _git(ci, "push", "-q", "origin", "feature")
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("BUILD_REASON", "PullRequest")
    monkeypatch.setenv("BUILD_SOURCESDIRECTORY", str(ci))
    monkeypatch.setenv("BUILD_SOURCEVERSION", head)
    monkeypatch.setenv("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feature")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_TARGETBRANCHNAME", "main")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_SOURCECOMMITID", head)

    # Its first parent is the request's own commit; diffing from there would
    # list c.yaml, which the merge brought in from main.
    assert diff_calculation(DiffSource.CHANGE_REQUEST) == ["objects/rules/b.yaml"]


@pytest.mark.parametrize("event_type", ["merged_result", "merge_train"])
@pytest.mark.parametrize("source_sha", [True, False], ids=["source-sha", "no-source-sha"])
def test_gitlab_merged_results_diff_the_merge_from_the_target_tip(
    request_checkout: Request, monkeypatch: pytest.MonkeyPatch, event_type: str, source_sha: bool
) -> None:
    """A merged results pipeline diffed from the merge base to the merged commit.

    The old code meant to diff to the request's head, but looked for the
    merged commit by ``CI_COMMIT_BEFORE_SHA``, which is all zeros in merge
    request pipelines, so it never did.
    """
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("CI_PIPELINE_SOURCE", "merge_request_event")
    monkeypatch.setenv("CI_PROJECT_DIR", str(request_checkout.ci))
    monkeypatch.setenv("CI_COMMIT_SHA", request_checkout.merge)
    monkeypatch.setenv("CI_COMMIT_BEFORE_SHA", "0" * 40)
    monkeypatch.setenv("CI_MERGE_REQUEST_DIFF_BASE_SHA", request_checkout.merge_base)
    monkeypatch.setenv("CI_MERGE_REQUEST_EVENT_TYPE", event_type)
    if source_sha:
        monkeypatch.setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", request_checkout.feature)

    assert diff_calculation(DiffSource.CHANGE_REQUEST) == ["objects/rules/b.yaml"]


def test_gitlab_detached_pipeline_diffs_from_the_merge_base(
    request_checkout: Request, monkeypatch: pytest.MonkeyPatch
) -> None:
    ci = request_checkout.ci
    _git(ci, "checkout", "-q", "--detach", request_checkout.feature)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("CI_PIPELINE_SOURCE", "merge_request_event")
    monkeypatch.setenv("CI_PROJECT_DIR", str(ci))
    monkeypatch.setenv("CI_COMMIT_SHA", request_checkout.feature)
    monkeypatch.setenv("CI_MERGE_REQUEST_DIFF_BASE_SHA", request_checkout.merge_base)
    monkeypatch.setenv("CI_MERGE_REQUEST_EVENT_TYPE", "detached")

    assert diff_calculation(DiffSource.CHANGE_REQUEST) == ["objects/rules/b.yaml"]


@dataclass(frozen=True)
class Push:
    """A default branch that received two commits in one push."""

    repo: Path
    before: str
    head: str


@pytest.fixture
def two_commit_push(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Push:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    before = _commit_rule(repo, "a.yaml", "name: a\n", "catalogue")
    # A rebase merge of a two-commit pull request lands both in one push.
    _commit_rule(repo, "b.yaml", "name: b\n", "request commit 1")
    head = _commit_rule(repo, "c.yaml", "name: c\n", "request commit 2")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(repo))
    monkeypatch.setenv("GITHUB_SHA", head)
    return Push(repo, before, head)


def _push_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))


def test_github_push_diffs_every_pushed_commit(
    two_commit_push: Push, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The push diff was ``HEAD^1..HEAD``: a rebase merge deployed only its last commit."""
    _push_event(tmp_path, monkeypatch, {"before": two_commit_push.before})

    assert sorted(diff_calculation(DiffSource.PUSH)) == [
        "objects/rules/b.yaml",
        "objects/rules/c.yaml",
    ]


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(None, id="no-event-file"),
        pytest.param({}, id="no-before"),
        pytest.param({"before": "0" * 40}, id="new-branch"),
        pytest.param({"before": "f" * 40}, id="not-in-checkout"),
        pytest.param(["not", "an", "object"], id="not-an-object"),
    ],
)
def test_github_push_without_a_usable_before_diffs_the_last_commit(
    two_commit_push: Push,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    if payload is not None:
        _push_event(tmp_path, monkeypatch, payload)

    assert diff_calculation(DiffSource.PUSH) == ["objects/rules/c.yaml"]


def test_github_push_with_an_unreadable_event_file_diffs_the_last_commit(
    two_commit_push: Push, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = tmp_path / "event.json"
    event.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))

    assert diff_calculation(DiffSource.PUSH) == ["objects/rules/c.yaml"]
