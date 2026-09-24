"""CI diff plans must return a sentence, not a leaked exception (#339)."""

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
_LEAKS = (
    "lookup_ref",
    "encode",
    "list index out of range",
    "KeyError while compiling the deployment plan",
    "Invalid object name",
)

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
)

_AZURE_REFS = (
    "Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and "
    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME | Ensure this is running in a Pull Request pipeline"
)


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _init_repo(path: Path, commits: int = 1) -> str:
    _git(path, "init", "-q", "-b", "main")
    for index in range(commits):
        (path / "README.md").write_text(f"rules {index}\n", encoding="utf-8")
        _git(path, "add", "README.md")
        _git(path, "commit", "-q", "-m", f"commit {index}")
    return _git(path, "rev-parse", "HEAD")


def _env(repo: Path, **values: str | None) -> dict[str, str | None]:
    env: dict[str, str | None] = {key: None for key in _HIDDEN}
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    env["OPENTIDE_TIDE_WORKSPACE"] = str(repo)
    env.update(values)
    return env


def _visible(result: object) -> str:
    rendered = result.stdout + result.stderr  # type: ignore[attr-defined]
    visible = _ANSI.sub("", rendered)
    return re.sub(r"[\u2500-\u257f]", "", visible)


def _assert_failure(result: object, message: str, *, json_output: bool) -> None:
    assert result.exit_code == 1, result.stdout + result.stderr  # type: ignore[attr-defined]
    rendered = result.stdout + result.stderr  # type: ignore[attr-defined]
    for leak in _LEAKS:
        assert leak not in rendered
    if json_output:
        payload = json.loads(result.stdout)  # type: ignore[attr-defined]
        assert payload["ok"] is False
        assert payload["message"] == message
    else:
        assert message in re.sub(r"\s+", " ", _visible(result))


@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_gitlab_missing_tip_names_ci_commit_sha(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, json_output: bool
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", "STAGING"],
        env=_env(repo, CI="true", CI_PROJECT_DIR=str(repo), CI_MERGE_REQUEST_DIFF_BASE_SHA=head),
    )
    _assert_failure(
        result, "CI_COMMIT_SHA is required to compute the changed rules", json_output=json_output
    )


@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_github_missing_tip_names_github_sha(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, json_output: bool
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo, commits=2)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", "PRODUCTION"],
        env=_env(repo, GITHUB_ACTIONS="true", GITHUB_WORKSPACE=str(repo)),
    )
    _assert_failure(
        result, "GITHUB_SHA is required to compute the changed rules", json_output=json_output
    )


@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_azure_missing_tip_names_build_sourceversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, json_output: bool
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo, commits=2)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", "PRODUCTION"],
        env=_env(repo, TF_BUILD="true", BUILD_SOURCESDIRECTORY=str(repo)),
    )
    _assert_failure(
        result,
        "BUILD_SOURCEVERSION is required to compute the changed rules",
        json_output=json_output,
    )


@pytest.mark.parametrize("with_origin", [False, True], ids=["no-origin", "origin"])
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_azure_staging_without_pr_refs_names_azure_variables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    with_origin: bool,
    json_output: bool,
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    if with_origin:
        origin = tmp_path / "origin.git"
        _git(tmp_path, "init", "-q", "--bare", str(origin))
        _git(repo, "remote", "add", "origin", str(origin))
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", "STAGING"],
        env=_env(
            repo,
            TF_BUILD="true",
            BUILD_SOURCESDIRECTORY=str(repo),
            BUILD_SOURCEVERSION=head,
        ),
    )
    _assert_failure(result, _AZURE_REFS, json_output=json_output)
    rendered = result.stdout + result.stderr
    assert "No git repository was found" not in rendered


@pytest.mark.parametrize(
    ("marker", "workspace", "tip_name", "tip_value"),
    [
        ("GITHUB_ACTIONS", "GITHUB_WORKSPACE", "GITHUB_SHA", "head"),
        ("TF_BUILD", "BUILD_SOURCESDIRECTORY", "BUILD_SOURCEVERSION", "head"),
    ],
    ids=["github", "azure"],
)
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_staging_missing_origin_ref_names_the_ref(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    marker: str,
    workspace: str,
    tip_name: str,
    tip_value: str,
    json_output: bool,
) -> None:
    del git_home, tip_value
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", str(origin))
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")
    monkeypatch.chdir(repo)
    extra = {
        marker: "true",
        workspace: str(repo),
        tip_name: head,
    }
    if marker == "GITHUB_ACTIONS":
        extra["GITHUB_HEAD_REF"] = "no-such"
        extra["GITHUB_BASE_REF"] = "also-missing"
    else:
        extra["SYSTEM_PULLREQUEST_SOURCEBRANCH"] = "no-such"
        extra["SYSTEM_PULLREQUEST_TARGETBRANCHNAME"] = "also-missing"
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", "STAGING"],
        env=_env(repo, **extra),
    )
    _assert_failure(result, "Could not find git ref origin/also-missing", json_output=json_output)


@pytest.mark.parametrize("plan", ["DEBUG", "MANUAL", "ALWAYS"])
@pytest.mark.parametrize(
    "platform",
    [
        {"CI": "true", "CI_PROJECT_DIR": "repo", "CI_COMMIT_SHA": "head"},
        {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": "repo", "GITHUB_SHA": "head"},
        {"TF_BUILD": "true", "BUILD_SOURCESDIRECTORY": "repo", "BUILD_SOURCEVERSION": "head"},
    ],
    ids=["gitlab", "github", "azure"],
)
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_non_diff_ci_plan_names_the_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    plan: str,
    platform: dict[str, str],
    json_output: bool,
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    values: dict[str, str | None] = {}
    for key, value in platform.items():
        if value == "repo":
            values[key] = str(repo)
        elif value == "head":
            values[key] = head
        else:
            values[key] = value
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", plan],
        env=_env(repo, **values),
    )
    _assert_failure(
        result,
        f"Deployment plan {plan} is not a CI diff plan. Use STAGING, PRODUCTION, or FULL.",
        json_output=json_output,
    )


def test_gitlab_merged_result_with_one_parent_keeps_the_tip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path
) -> None:
    """A one-parent ``CI_COMMIT_BEFORE_SHA`` must not index ``parents[1]``."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    _git(repo, "checkout", "-q", "-b", "feature")
    (repo / "README.md").write_text("feature\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "feature")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "--no-ff", "-q", "-m", "merge feature", "feature")
    head = _git(repo, "rev-parse", "HEAD")
    parent = _git(repo, "rev-parse", "HEAD^1")
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--plan", "STAGING"],
        env=_env(
            repo,
            CI="true",
            CI_PROJECT_DIR=str(repo),
            CI_COMMIT_SHA=head,
            CI_COMMIT_BEFORE_SHA=parent,
            CI_MERGE_REQUEST_DIFF_BASE_SHA=parent,
            CI_MERGE_REQUEST_EVENT_TYPE="merged_result",
        ),
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert "list index out of range" not in result.stdout
