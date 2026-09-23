"""CI STAGING/PRODUCTION plans outside a git checkout (#310)."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.deployment.git_repo import missing_checkout_message

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_MARKERS = ("GITHUB_ACTIONS", "CI", "TF_BUILD")
_WORKSPACE_VARS = {
    "GITHUB_ACTIONS": "GITHUB_WORKSPACE",
    "CI": "CI_PROJECT_DIR",
    "TF_BUILD": "BUILD_SOURCESDIRECTORY",
}


def _ci_env(tmp_path: Path, marker: str) -> dict[str, str | None]:
    """Enable one CI marker and clear the others.

    ``CliRunner`` overlays ``env`` on ``os.environ``. A key that is only
    omitted stays set, so a GitHub-hosted run would keep ``GITHUB_WORKSPACE``
    and open that checkout instead of reporting the missing one.
    """
    hidden = {
        *_MARKERS,
        *_WORKSPACE_VARS.values(),
        "OPENTIDE_REPO_ROOT",
        "OPENTIDE_TIDE_WORKSPACE",
    }
    env: dict[str, str | None] = {key: None for key in hidden}
    env[marker] = "true"
    env["OPENTIDE_REPO_ROOT"] = str(tmp_path)
    env["OPENTIDE_TIDE_WORKSPACE"] = str(tmp_path)
    return env


@pytest.mark.parametrize("plan", ["STAGING", "PRODUCTION"])
@pytest.mark.parametrize("marker", list(_WORKSPACE_VARS))
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_ci_plan_without_a_checkout_names_the_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    plan: str,
    marker: str,
    json_output: bool,
) -> None:
    """#310: ``open_repo(None)`` reported ``No git repository was found at None``."""
    monkeypatch.chdir(tmp_path)
    message = missing_checkout_message(plan, tmp_path.resolve())
    argv = [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", plan]

    result = runner.invoke(app, argv, env=_ci_env(tmp_path, marker))

    assert result.exit_code == 1, result.stdout + result.stderr
    if json_output:
        payload = json.loads(result.stdout)
        assert payload["ok"] is False
        assert payload["message"] == message
    else:
        rendered = result.stdout + result.stderr
        # Plain mode prints ``FATAL: <message>``. A Rich panel titles itself
        # FATAL and wraps the sentence between border characters.
        assert "FATAL" in rendered
        visible = _ANSI.sub("", rendered)
        visible = re.sub(r"[\u2500-\u257f]", "", visible)
        assert re.sub(r"\s+", "", message) in re.sub(r"\s+", "", visible)


def test_full_plan_in_ci_does_not_need_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--plan", "FULL"],
        env=_ci_env(tmp_path, "GITHUB_ACTIONS"),
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "skipped"
    assert "no .git was found" not in payload["message"]


def test_a_real_checkout_is_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path
) -> None:
    """The missing-checkout error is only for a tree with no ``.git``."""
    del git_home
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("rules\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    for name in ("CI", "TF_BUILD", "CI_PROJECT_DIR", "BUILD_SOURCESDIRECTORY"):
        monkeypatch.delenv(name, raising=False)

    from opentide.deployment.git_repo import GitRepository

    opened = GitRepository()
    assert opened.repository is not None
    assert opened.repository.path.resolve() == tmp_path.resolve()
