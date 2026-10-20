"""GitLab merge request and push runs when the base SHA is missing (#333).

A merge request pipeline (``CI_PIPELINE_SOURCE=merge_request_event``) diffs from
``CI_MERGE_REQUEST_DIFF_BASE_SHA``; any other pipeline from ``CI_COMMIT_BEFORE_SHA``.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_HIDDEN = (
    "GITHUB_ACTIONS",
    "GITHUB_WORKSPACE",
    "GITHUB_SHA",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "TF_BUILD",
    "BUILD_SOURCESDIRECTORY",
    "BUILD_SOURCEVERSION",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
    "CI",
    "CI_PROJECT_DIR",
    "CI_COMMIT_SHA",
    "CI_COMMIT_BEFORE_SHA",
    "CI_MERGE_REQUEST_DIFF_BASE_SHA",
    "CI_MERGE_REQUEST_EVENT_TYPE",
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "DEPLOYMENT_PLAN",
    "CI_PIPELINE_SOURCE",
)

#: run -> (``--strategy`` of the generated job, variables, the base SHA variable).
_RUNS = {
    "merge-request": (
        "PREVIEW",
        {"CI_PIPELINE_SOURCE": "merge_request_event"},
        "CI_MERGE_REQUEST_DIFF_BASE_SHA",
    ),
    "push": ("RELEASE", {"CI_PIPELINE_SOURCE": "push"}, "CI_COMMIT_BEFORE_SHA"),
}


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return done.stdout.strip()


def _init_repo(path: Path) -> str:
    _git(path, "init", "-q", "-b", "main")
    (path / "README.md").write_text("rules\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-q", "-m", "init")
    return _git(path, "rev-parse", "HEAD")


def _gitlab_env(repo: Path, head: str, **overrides: str | None) -> dict[str, str | None]:
    env: dict[str, str | None] = {key: None for key in _HIDDEN}
    env.update(
        {
            "CI": "true",
            "CI_PROJECT_DIR": str(repo),
            "CI_COMMIT_SHA": head,
            "OPENTIDE_REPO_ROOT": str(repo),
            "OPENTIDE_TIDE_WORKSPACE": str(repo),
        }
    )
    env.update(overrides)
    return env


def _visible(result: object) -> str:
    rendered = result.stdout + result.stderr  # type: ignore[attr-defined]
    visible = _ANSI.sub("", rendered)
    visible = re.sub(r"[\u2500-\u257f]", "", visible)
    return re.sub(r"\s+", " ", visible)


@pytest.mark.parametrize(
    ("run", "base"),
    [
        ("merge-request", None),
        ("merge-request", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        # An unset or all-zeros CI_COMMIT_BEFORE_SHA diffs from HEAD's parent instead.
        ("push", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ],
    ids=["unset-merge-request", "unknown-merge-request", "unknown-push"],
)
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_gitlab_missing_base_names_no_source_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    run: str,
    base: str | None,
    json_output: bool,
) -> None:
    """#333: a missing base walked ``origin/main`` via ``Repo.lookup_ref``."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    strategy, variables, base_var = _RUNS[run]
    argv = [*(["--json"] if json_output else []), "deploy", "--dry-run", "--strategy", strategy]
    result = runner.invoke(app, argv, env=_gitlab_env(repo, head, **variables, **{base_var: base}))

    assert result.exit_code == 1, result.stdout + result.stderr
    rendered = result.stdout + result.stderr
    assert "lookup_ref" not in rendered
    assert "AttributeError" not in rendered
    if json_output:
        payload = json.loads(result.stdout)
        assert payload["ok"] is False
        assert payload["message"] == "No Source Commit Found"
    else:
        assert "No Source Commit Found" in _visible(result)


@pytest.mark.parametrize("run", list(_RUNS))
def test_gitlab_run_succeeds_when_both_shas_are_in_the_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    run: str,
) -> None:
    """The same command already succeeds when the base commit is in the repo."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    base = _init_repo(repo)
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "second")
    head = _git(repo, "rev-parse", "HEAD")
    monkeypatch.chdir(repo)
    strategy, variables, base_var = _RUNS[run]
    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--strategy", strategy],
        env=_gitlab_env(repo, head, **variables, **{base_var: base}),
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert "lookup_ref" not in result.stdout


@pytest.mark.parametrize("base", [None, "0" * 40], ids=["unset", "zeros"])
def test_gitlab_push_without_a_previous_tip_diffs_from_the_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    base: str | None,
) -> None:
    """GitLab sends all zeros on a branch's first push, a manual run and a schedule.

    There is no previous tip to diff from, so the push diffs from HEAD's first
    parent, as on GitHub and Azure, instead of failing with No Source Commit Found.
    """
    del git_home
    from opentide.deployment.git_repo import DiffSource, diff_calculation, run_diff_source

    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    rules = repo / "objects" / "rules"
    rules.mkdir(parents=True)
    (rules / "changed.yaml").write_text("name: changed\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "second")
    head = _git(repo, "rev-parse", "HEAD")
    for name, value in _gitlab_env(repo, head, CI_COMMIT_BEFORE_SHA=base).items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)

    assert run_diff_source() is DiffSource.PUSH
    assert diff_calculation(DiffSource.PUSH) == ["objects/rules/changed.yaml"]


def test_gitlab_unknown_base_still_names_no_source_when_origin_main_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
) -> None:
    """Walking ``origin/main`` must not raise when the ref exists and the SHA does not."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", str(origin))
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--strategy", "PREVIEW"],
        env=_gitlab_env(
            repo,
            head,
            CI_PIPELINE_SOURCE="merge_request_event",
            CI_MERGE_REQUEST_DIFF_BASE_SHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    )
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["message"] == "No Source Commit Found"
    assert "lookup_ref" not in result.stdout


@pytest.mark.parametrize(
    ("strategy", "source"),
    [("PREVIEW", "merge_request_event"), ("RELEASE", "merge_request_event"), ("PREVIEW", "push")],
    ids=["PREVIEW-merge-request", "RELEASE-merge-request", "PREVIEW-push"],
)
def test_the_pipeline_not_the_strategy_picks_the_gitlab_base(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    strategy: str,
    source: str,
) -> None:
    """A merge request pipeline reads ``CI_MERGE_REQUEST_DIFF_BASE_SHA`` whatever ``--strategy``."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    unknown = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    # Only the base the pipeline reads is unknown; the other one is the tip.
    if source == "merge_request_event":
        bases = {"CI_MERGE_REQUEST_DIFF_BASE_SHA": unknown, "CI_COMMIT_BEFORE_SHA": head}
    else:
        bases = {"CI_MERGE_REQUEST_DIFF_BASE_SHA": head, "CI_COMMIT_BEFORE_SHA": unknown}
    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--strategy", strategy],
        env=_gitlab_env(repo, head, CI_PIPELINE_SOURCE=source, **bases),
    )
    assert result.exit_code == 1, result.stdout + result.stderr
    assert json.loads(result.stdout)["message"] == "No Source Commit Found"
