"""``share push --changed`` reads the branch tip after the production write-back (#590).

The generated share job runs after the production job and checks out the
default branch, which then holds the ``[skip ci]`` commit that records promoted
statuses. The diff starts where the triggering push's diff starts and ends at
that tip, so a rule the deploy promoted is shared in the same pipeline run.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

_HIDDEN = (
    "CI",
    "GITHUB_ACTIONS",
    "GITHUB_EVENT_NAME",
    "GITHUB_WORKSPACE",
    "GITHUB_SHA",
    "TF_BUILD",
    "BUILD_REASON",
    "BUILD_SOURCESDIRECTORY",
    "BUILD_SOURCEVERSION",
    "CI_PROJECT_DIR",
    "CI_COMMIT_SHA",
    "CI_COMMIT_BEFORE_SHA",
    "CI_PIPELINE_SOURCE",
)


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for name, body in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def promoted_repo(tmp_path: Path, git_home: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """``before`` -> ``trigger`` (adds a STAGING rule) -> ``writeback`` (promotes it).

    ``HEAD`` is the write-back, as in the share job's checkout of the tip.
    """
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    before = _commit(repo, {"objects/rules/old.yaml": "status: PRODUCTION\n"}, "an earlier rule")
    trigger = _commit(
        repo,
        {
            "objects/rules/new.yaml": "status: STAGING\n",
            "objects/threats/threat.yaml": "name: t\n",
        },
        "Merge: add a STAGING rule",
    )
    writeback = _commit(
        repo,
        {
            "objects/rules/new.yaml": "status: PRODUCTION\n",
            "objects/rules/also-promoted.yaml": "status: PRODUCTION\n",
        },
        "ci: record production deployment [skip ci]",
    )
    for name in _HIDDEN:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    # The repo root is cached per process; the workspace variable wins over it.
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    monkeypatch.chdir(repo)
    return {"repo": repo, "before": before, "trigger": trigger, "writeback": writeback}


_TRIGGERED = ["objects/rules/new.yaml", "objects/threats/threat.yaml"]
_THROUGH_TIP = sorted([*_TRIGGERED, "objects/rules/also-promoted.yaml"])


@pytest.mark.parametrize("provider", ["github", "azure", "gitlab"])
def test_the_diff_spans_the_push_and_the_writeback(
    promoted_repo: dict, monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    from opentide.deployment.git_repo import changed_through_head

    repo, trigger = promoted_repo["repo"], promoted_repo["trigger"]
    if provider == "github":
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_WORKSPACE", str(repo))
        monkeypatch.setenv("GITHUB_SHA", trigger)
    elif provider == "azure":
        monkeypatch.setenv("TF_BUILD", "True")
        monkeypatch.setenv("BUILD_SOURCESDIRECTORY", str(repo))
        monkeypatch.setenv("BUILD_SOURCEVERSION", trigger)
    else:
        monkeypatch.setenv("CI", "true")
        monkeypatch.setenv("CI_PROJECT_DIR", str(repo))
        monkeypatch.setenv("CI_COMMIT_SHA", trigger)
        monkeypatch.setenv("CI_COMMIT_BEFORE_SHA", promoted_repo["before"])

    assert sorted(changed_through_head()) == _THROUGH_TIP


@pytest.mark.parametrize("before", [None, "0" * 40], ids=["unset", "zeros"])
def test_gitlab_without_a_previous_tip_diffs_from_the_triggering_parent(
    promoted_repo: dict, monkeypatch: pytest.MonkeyPatch, before: str | None
) -> None:
    from opentide.deployment.git_repo import changed_through_head

    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("CI_PROJECT_DIR", str(promoted_repo["repo"]))
    monkeypatch.setenv("CI_COMMIT_SHA", promoted_repo["trigger"])
    if before is not None:
        monkeypatch.setenv("CI_COMMIT_BEFORE_SHA", before)
    assert sorted(changed_through_head()) == _THROUGH_TIP


def test_a_job_on_the_triggering_commit_keeps_the_push_diff(
    promoted_repo: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no write-back yet, ``HEAD`` is the pushed commit: the diff is the push's."""
    from opentide.deployment.git_repo import changed_through_head

    repo = promoted_repo["repo"]
    _git(repo, "checkout", "-q", promoted_repo["trigger"])
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(repo))
    monkeypatch.setenv("GITHUB_SHA", promoted_repo["trigger"])
    assert sorted(changed_through_head()) == _TRIGGERED


def test_since_names_the_base_in_and_outside_ci(
    promoted_repo: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.deployment.git_repo import changed_through_head

    assert sorted(changed_through_head(promoted_repo["trigger"])) == [
        "objects/rules/also-promoted.yaml",
        "objects/rules/new.yaml",
    ]
    assert sorted(changed_through_head(promoted_repo["before"])) == _THROUGH_TIP
    # A branch name resolves too.
    _git(promoted_repo["repo"], "branch", "base", promoted_repo["before"])
    assert sorted(changed_through_head("base")) == _THROUGH_TIP
    with pytest.raises(Exception, match="Could not find git commit nope"):
        changed_through_head("nope")
    with pytest.raises(Exception, match="--since"):
        changed_through_head()

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(promoted_repo["repo"]))
    monkeypatch.setenv("GITHUB_SHA", promoted_repo["writeback"])
    assert sorted(changed_through_head(promoted_repo["before"])) == _THROUGH_TIP


def test_a_root_trigger_or_a_missing_variable(
    tmp_path: Path, git_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del git_home
    from opentide.deployment.git_repo import changed_through_head

    repo = tmp_path / "root"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    root = _commit(repo, {"objects/rules/r.yaml": "status: STAGING\n"}, "init")
    for name in _HIDDEN:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("BUILD_SOURCESDIRECTORY", str(repo))
    with pytest.raises(Exception, match="BUILD_SOURCEVERSION is required"):
        changed_through_head()
    monkeypatch.setenv("BUILD_SOURCEVERSION", root)
    assert changed_through_head() == []


def test_since_needs_changed_and_a_value(invoke_cli, tide_corpus_repo: Path) -> None:
    alone = invoke_cli("share", "push", "--since", "abc", repo=tide_corpus_repo)
    assert alone.exit_code == 2, alone.stdout
    assert "--since needs --changed" in alone.stdout
    assert json.loads(alone.stdout)["failure"]["code"] == "usage_missing_option"
    blank = invoke_cli("share", "push", "--changed", "--since", " ", repo=tide_corpus_repo)
    assert blank.exit_code == 2, blank.stdout
    assert "--since needs a commit" in blank.stdout
    assert json.loads(blank.stdout)["failure"]["code"] == "usage_invalid_value"


def test_since_runs_outside_ci_and_reaches_the_diff(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_cli.test_share import _OUTSIDE_CI, KEY, _Persistent, _write_sharing

    monkeypatch.setenv("MISP_LAB_KEY", KEY)
    monkeypatch.setattr("opentide.sharing.engine.PyMispClient", _Persistent)
    monkeypatch.setattr(_Persistent, "events", [])
    _write_sharing(tide_corpus_repo)
    asked: list[object] = []

    def _diff(since: object) -> list[str]:
        asked.append(since)
        return []

    monkeypatch.setattr("opentide.deployment.git_repo.changed_through_head", _diff)
    result = invoke_cli(
        "share",
        "push",
        "--changed",
        "--since",
        "deadbeef",
        repo=tide_corpus_repo,
        extra_env=_OUTSIDE_CI,
    )
    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["message"] == "No changed objects to share"
    assert asked == ["deadbeef"]
    assert _Persistent.events == []


def test_since_peels_an_annotated_tag(promoted_repo: dict) -> None:
    """``refs/tags/<tag>`` names a tag object for an annotated tag, not a commit."""
    from opentide.deployment.git_repo import changed_through_head

    repo = promoted_repo["repo"]
    _git(repo, "tag", "-a", "v1", "-m", "release", promoted_repo["before"])
    _git(repo, "tag", "-a", "v1-again", "-m", "tag of a tag", "v1")
    _git(repo, "tag", "light", promoted_repo["before"])
    assert sorted(changed_through_head("refs/tags/v1")) == _THROUGH_TIP
    assert sorted(changed_through_head("refs/tags/v1-again")) == _THROUGH_TIP
    assert sorted(changed_through_head("refs/tags/light")) == _THROUGH_TIP
