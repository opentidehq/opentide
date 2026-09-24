"""GitHub STAGING without pull-request refs (#334)."""

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

_MESSAGE = (
    "Expected to find GITHUB_HEAD_REF and GITHUB_BASE_REF"
    " | Ensure this is running in a Pull Request pipeline"
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


def _github_env(repo: Path, head: str) -> dict[str, str | None]:
    env: dict[str, str | None] = {key: None for key in _HIDDEN}
    env.update(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(repo),
            "GITHUB_SHA": head,
            "OPENTIDE_REPO_ROOT": str(repo),
            "OPENTIDE_TIDE_WORKSPACE": str(repo),
        }
    )
    return env


def _visible(result: object) -> str:
    rendered = result.stdout + result.stderr  # type: ignore[attr-defined]
    visible = _ANSI.sub("", rendered)
    visible = re.sub(r"[\u2500-\u257f]", "", visible)
    return re.sub(r"\s+", " ", visible)


@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_github_staging_without_pr_refs_names_github_variables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    json_output: bool,
) -> None:
    """#334: missing GitHub refs asked for Azure variables, then KeyError."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("rules\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "init")
    head = _git(repo, "rev-parse", "HEAD")
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", str(origin))
    _git(repo, "remote", "add", "origin", str(origin))
    monkeypatch.chdir(repo)
    argv = [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", "STAGING"]
    result = runner.invoke(app, argv, env=_github_env(repo, head))

    assert result.exit_code == 1, result.stdout + result.stderr
    rendered = result.stdout + result.stderr
    assert "SYSTEM_PULLREQUEST" not in rendered
    assert "KeyError" not in rendered
    if json_output:
        payload = json.loads(result.stdout)
        assert payload["ok"] is False
        assert payload["message"] == _MESSAGE
        assert "GITHUB_HEAD_REF" in payload["message"]
        assert "GITHUB_BASE_REF" in payload["message"]
    else:
        visible = _visible(result)
        assert "GITHUB_HEAD_REF" in visible
        assert "GITHUB_BASE_REF" in visible
        assert _MESSAGE.replace(" ", "") in visible.replace(" ", "")
