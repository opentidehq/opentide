"""CLI E2E: the generated pre-commit hook, exercised by a real ``git commit``.

``test_setup_hooks.py`` asserts the hook *files* exist. That is why #249 and
#250 shipped: nothing ever ran the hook, and every fixture exports
``OPENTIDE_REPO_ROOT`` at the test repo, which is precisely the variable that
made the hook validate the wrong tree.

These tests run the installed console script as a child process and let Git
invoke the hook, with ``OPENTIDE_REPO_ROOT`` unset (the real commit
environment) and then pointed at a different detection repository.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from pytest_console_scripts import RunResult, ScriptRunner
from tests.test_cli.e2e.helpers import write_tutorial_objects

pytestmark = [
    pytest.mark.cli_smoke,
    pytest.mark.script_launch_mode("subprocess"),
]

BROKEN_YAML = "name: [\n"
BROKEN_RELPATH = "objects/rules/not-yaml.yaml"


def _clean_env(**overrides: str) -> dict[str, str]:
    """The environment a developer commits in: no OpenTide exports."""
    env = os.environ.copy()
    for name in (
        "OPENTIDE_REPO_ROOT",
        "OPENTIDE_TIDE_WORKSPACE",
        "OPENTIDE_SKIP_HOOKS",
        "DEPLOYMENT_PLAN",
    ):
        env.pop(name, None)
    env.update(overrides)
    return env


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env if env is not None else _clean_env(),
        capture_output=True,
        text=True,
        check=False,
    )


def _commit(repo: Path, message: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    staged = _git(repo, "add", "-A", env=env)
    assert staged.returncode == 0, staged.stderr
    return _git(repo, "commit", "-m", message, env=env)


def _scaffold(script_runner: ScriptRunner, repo: Path) -> None:
    """A detection repository with the hook installed and one valid commit."""
    repo.mkdir(parents=True, exist_ok=True)
    init = _git(repo, "init", "-b", "main")
    assert init.returncode == 0, init.stderr
    _git(repo, "config", "user.email", "e2e@opentide.local")
    _git(repo, "config", "user.name", "OpenTide E2E")

    setup: RunResult = script_runner.run(
        ["opentide", "--json", "setup", "--yes", "--platform", "sentinel", "--path", str(repo)],
        env=_clean_env(),
        print_result=False,
    )
    assert setup.returncode == 0, setup.stdout + setup.stderr

    hooks: RunResult = script_runner.run(
        ["opentide", "--json", "setup", "hooks", str(repo), "--yes"],
        env=_clean_env(),
        print_result=False,
    )
    assert hooks.returncode == 0, hooks.stdout + hooks.stderr
    assert (repo / ".git" / "hooks" / "pre-commit").is_file()


def test_hook_lets_a_valid_commit_through(script_runner: ScriptRunner, tmp_path: Path) -> None:
    repo = tmp_path / "detections"
    _scaffold(script_runner, repo)
    write_tutorial_objects(repo)

    result = _commit(repo, "add tutorial objects", _clean_env())
    assert result.returncode == 0, result.stdout + result.stderr
    assert _git(repo, "rev-parse", "HEAD").returncode == 0


def test_hook_blocks_unparseable_yaml_without_a_traceback(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """#250: the hook used to die with a ParserError stack instead of an error."""
    repo = tmp_path / "detections"
    _scaffold(script_runner, repo)
    write_tutorial_objects(repo)
    assert _commit(repo, "baseline", _clean_env()).returncode == 0

    (repo / BROKEN_RELPATH).write_text(BROKEN_YAML, encoding="utf-8")
    result = _commit(repo, "commit broken yaml", _clean_env())
    output = result.stdout + result.stderr

    assert result.returncode != 0, f"broken YAML was committed\n{output}"
    assert "Traceback (most recent call last)" not in output, output
    assert "ParserError" not in output, output
    assert "Could not parse object YAML" in output, output


def test_hook_validates_the_worktree_not_opentide_repo_root(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """#249: with the env var pointing elsewhere the hook passed broken content.

    ``get_repo_root`` reads ``OPENTIDE_REPO_ROOT`` before it discovers the
    worktree, and ``.env.example`` tells users to export it. A hook that does
    not pin ``--repo`` validates whatever that variable names.
    """
    other = tmp_path / "other-detections"
    repo = tmp_path / "detections"
    _scaffold(script_runner, other)
    _scaffold(script_runner, repo)
    write_tutorial_objects(repo)
    assert _commit(repo, "baseline", _clean_env()).returncode == 0

    (repo / BROKEN_RELPATH).write_text(BROKEN_YAML, encoding="utf-8")
    env = _clean_env(OPENTIDE_REPO_ROOT=str(other), OPENTIDE_TIDE_WORKSPACE=str(other))
    result = _commit(repo, "commit broken yaml", env)
    output = result.stdout + result.stderr

    assert result.returncode != 0, (
        "the hook validated OPENTIDE_REPO_ROOT instead of the committed worktree; "
        f"broken YAML in {repo} was committed\n{output}"
    )
    assert str(repo) in output, output


def test_hook_still_honours_the_documented_bypass(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    repo = tmp_path / "detections"
    _scaffold(script_runner, repo)
    (repo / BROKEN_RELPATH).write_text(BROKEN_YAML, encoding="utf-8")

    result = _commit(repo, "bypass", _clean_env(OPENTIDE_SKIP_HOOKS="1"))
    assert result.returncode == 0, result.stdout + result.stderr


def _scaffold_nested(script_runner: ScriptRunner, mono: Path, workspace: Path) -> RunResult:
    """A detection workspace in a subdirectory of a larger Git repository."""
    mono.mkdir(parents=True, exist_ok=True)
    assert _git(mono, "init", "-b", "main").returncode == 0
    _git(mono, "config", "user.email", "e2e@opentide.local")
    _git(mono, "config", "user.name", "OpenTide E2E")
    (mono / "README.md").write_text("monorepo\n", encoding="utf-8")
    setup: RunResult = script_runner.run(
        [
            "opentide",
            "--json",
            "setup",
            "--yes",
            "--platform",
            "sentinel",
            "--path",
            str(workspace),
        ],
        env=_clean_env(),
        print_result=False,
    )
    assert setup.returncode == 0, setup.stdout + setup.stderr
    hooks: RunResult = script_runner.run(
        ["opentide", "--json", "setup", "hooks", str(workspace), "--yes"],
        env=_clean_env(),
        print_result=False,
    )
    assert hooks.returncode == 0, hooks.stdout + hooks.stderr
    write_tutorial_objects(workspace)
    return hooks


def test_hook_is_installed_for_a_workspace_nested_in_the_repo(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """A workspace below the Git root has no ``.git`` of its own.

    Setup looked only for ``<workspace>/.git``, reported "Not a Git
    repository", and installed nothing, so every commit went unvalidated.
    """
    mono = tmp_path / "mono"
    workspace = mono / "security" / "detections"
    hooks = _scaffold_nested(script_runner, mono, workspace)
    assert (mono / ".git" / "hooks" / "pre-commit").is_file(), hooks.stdout
    assert "Not a Git repository" not in hooks.stdout, hooks.stdout
    assert _commit(mono, "baseline", _clean_env()).returncode == 0

    (workspace / BROKEN_RELPATH).write_text(BROKEN_YAML, encoding="utf-8")
    result = _commit(mono, "commit broken yaml", _clean_env())
    output = result.stdout + result.stderr
    assert result.returncode != 0, f"broken YAML in a nested workspace was committed\n{output}"
    assert "Could not parse object YAML" in output, output


def test_versioned_hook_validates_the_nested_workspace_not_the_git_root(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """Pinning ``--repo`` to ``git rev-parse --show-toplevel`` named the monorepo root.

    That tree has no detection objects, so ``validate --strict`` passed with
    nothing checked, whichever way the versioned hook was wired in.
    """
    mono = tmp_path / "mono"
    workspace = mono / "detections"
    _scaffold_nested(script_runner, mono, workspace)
    installed = mono / ".git" / "hooks" / "pre-commit"
    installed.unlink(missing_ok=True)
    assert _git(mono, "config", "core.hooksPath", "detections/.opentide/hooks").returncode == 0
    assert _commit(mono, "baseline", _clean_env()).returncode == 0

    (workspace / BROKEN_RELPATH).write_text(BROKEN_YAML, encoding="utf-8")
    result = _commit(mono, "commit broken yaml", _clean_env())
    output = result.stdout + result.stderr
    assert result.returncode != 0, f"the hook validated the monorepo root\n{output}"
    assert "Could not parse object YAML" in output, output


def test_hook_fails_when_the_pinned_workspace_was_moved(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """``validate --strict`` on the old, now missing path passed every later commit."""
    mono = tmp_path / "mono"
    workspace = mono / "detections"
    _scaffold_nested(script_runner, mono, workspace)
    assert _commit(mono, "baseline", _clean_env()).returncode == 0

    workspace.rename(mono / "renamed")
    result = _commit(mono, "move the workspace", _clean_env())
    output = result.stdout + result.stderr

    assert result.returncode != 0, f"a hook pinned to a moved workspace passed\n{output}"
    assert "No OpenTide workspace at" in output, output
    assert "opentide setup hooks" in output, output


def test_pre_commit_entry_pins_the_nested_workspace(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """pre-commit runs every entry from the Git root, so the entry must name the subdirectory."""
    mono = tmp_path / "mono"
    workspace = mono / "detections"
    hooks = _scaffold_nested(script_runner, mono, workspace)
    config = (workspace / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    entry = next(line for line in config.splitlines() if "entry:" in line)
    assert "/detections" in entry, entry
    assert "repository root" in hooks.stdout, hooks.stdout


def test_pre_commit_entry_pins_the_worktree(script_runner: ScriptRunner, tmp_path: Path) -> None:
    """The pre-commit framework path must pin the repo the same way the shim does."""
    repo = tmp_path / "detections"
    _scaffold(script_runner, repo)
    config = (repo / ".pre-commit-config.yaml").read_text(encoding="utf-8")

    entry = next(line for line in config.splitlines() if "entry:" in line)
    assert "--repo" in entry, entry
    assert "git rev-parse --show-toplevel" in entry, entry


def test_setup_hooks_refreshes_a_legacy_entry(script_runner: ScriptRunner, tmp_path: Path) -> None:
    """Re-running setup must fix an existing config, not skip it as already present."""
    repo = tmp_path / "detections"
    _scaffold(script_runner, repo)
    config = repo / ".pre-commit-config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            next(
                line.strip()
                for line in config.read_text(encoding="utf-8").splitlines()
                if "entry:" in line
            ),
            "entry: opentide validate --strict",
        ),
        encoding="utf-8",
    )
    assert "entry: opentide validate --strict" in config.read_text(encoding="utf-8")

    refreshed: RunResult = script_runner.run(
        ["opentide", "--json", "setup", "hooks", str(repo), "--yes"],
        env=_clean_env(),
        print_result=False,
    )
    assert refreshed.returncode == 0, refreshed.stdout + refreshed.stderr
    assert "--repo" in config.read_text(encoding="utf-8")
