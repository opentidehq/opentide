"""GitLab STAGING/PRODUCTION when the base SHA is missing (#333)."""

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
)


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


@pytest.mark.parametrize("plan", ["STAGING", "PRODUCTION"])
@pytest.mark.parametrize(
    "base",
    [None, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    ids=["unset", "unknown"],
)
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_gitlab_missing_base_names_no_source_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    plan: str,
    base: str | None,
    json_output: bool,
) -> None:
    """#333: a missing base walked ``origin/main`` via ``Repo.lookup_ref``."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    base_var = "CI_MERGE_REQUEST_DIFF_BASE_SHA" if plan == "STAGING" else "CI_COMMIT_BEFORE_SHA"
    argv = [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", plan]
    result = runner.invoke(app, argv, env=_gitlab_env(repo, head, **{base_var: base}))

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


@pytest.mark.parametrize("plan", ["STAGING", "PRODUCTION"])
def test_gitlab_plan_succeeds_when_both_shas_are_in_the_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    plan: str,
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
    base_var = "CI_MERGE_REQUEST_DIFF_BASE_SHA" if plan == "STAGING" else "CI_COMMIT_BEFORE_SHA"
    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--plan", plan],
        env=_gitlab_env(repo, head, **{base_var: base}),
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert "lookup_ref" not in result.stdout


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
        ["--json", "deploy", "--dry-run", "--plan", "STAGING"],
        env=_gitlab_env(
            repo,
            head,
            CI_MERGE_REQUEST_DIFF_BASE_SHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    )
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["message"] == "No Source Commit Found"
    assert "lookup_ref" not in result.stdout
