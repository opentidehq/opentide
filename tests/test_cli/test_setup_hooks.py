"""Tests for ``opentide setup hooks``."""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.setup.hooks import (
    HOOK_ENTRY,
    HOOK_MARKER,
    HooksSetupOptions,
    _yaml_value,
    hook_entry,
    pre_commit_script,
    run_hooks_setup,
)

runner = CliRunner()


def _git_init(path: Path) -> Path:
    """A real repository: setup asks Git where the hooks live."""
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path / ".git" / "hooks"


def test_run_hooks_setup_writes_config_and_versioned_hook(tmp_path: Path) -> None:
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    config = tmp_path / ".pre-commit-config.yaml"
    hook = tmp_path / ".opentide" / "hooks" / "pre-commit"
    assert config.is_file()
    text = config.read_text(encoding="utf-8")
    assert "id: opentide-validate" in text
    assert f"entry: {HOOK_ENTRY}" in text
    assert hook.is_file()
    script = hook.read_text(encoding="utf-8")
    assert HOOK_MARKER in script
    # #249: the hook must pin the worktree, not inherit OPENTIDE_REPO_ROOT.
    assert 'opentide --repo "$OPENTIDE_HOOK_REPO" validate --strict' in script
    assert "git rev-parse --show-toplevel" in script
    assert os.access(hook, os.X_OK)
    assert result["installed"] is False
    assert "Not a Git repository" in result["warnings"][0]
    assert ".pre-commit-config.yaml" in result["files"]
    assert ".opentide/hooks/pre-commit" in result["files"]


def test_run_hooks_setup_installs_git_hook(tmp_path: Path) -> None:
    _git_init(tmp_path)
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    git_hook = tmp_path / ".git" / "hooks" / "pre-commit"
    assert git_hook.is_file()
    assert HOOK_MARKER in git_hook.read_text(encoding="utf-8")
    assert os.access(git_hook, os.X_OK)
    assert result["installed"] is True
    assert ".git/hooks/pre-commit" in result["files"]
    assert "warnings" not in result


def test_run_hooks_setup_does_not_clobber_foreign_git_hook(tmp_path: Path) -> None:
    hooks_dir = _git_init(tmp_path)
    foreign = hooks_dir / "pre-commit"
    foreign.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
    assert result["installed"] is False
    assert "left unchanged" in result["warnings"][0]
    assert (tmp_path / ".opentide" / "hooks" / "pre-commit").is_file()


def test_run_hooks_setup_refreshes_managed_git_hook(tmp_path: Path) -> None:
    hooks_dir = _git_init(tmp_path)
    (hooks_dir / "pre-commit").write_text(
        f"#!/bin/sh\n# {HOOK_MARKER}\necho stale\n",
        encoding="utf-8",
    )
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    text = (tmp_path / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert 'opentide --repo "$OPENTIDE_HOOK_REPO" validate --strict' in text
    assert "echo stale" not in text
    assert result["installed"] is True


def test_run_hooks_setup_no_install_skips_git_hook(tmp_path: Path) -> None:
    _git_init(tmp_path)
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=False))
    assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()
    assert result["installed"] is False
    assert (tmp_path / ".pre-commit-config.yaml").is_file()


def test_run_hooks_setup_is_idempotent(tmp_path: Path) -> None:
    _git_init(tmp_path)
    run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    second = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    assert second["files"] == []
    assert ".pre-commit-config.yaml" in second["skipped"]
    assert ".opentide/hooks/pre-commit" in second["skipped"]
    assert ".git/hooks/pre-commit" in second["skipped"]


def test_run_hooks_setup_merges_existing_pre_commit_config(tmp_path: Path) -> None:
    (tmp_path / ".pre-commit-config.yaml").write_text(
        "repos:\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n    hooks:\n"
        "      - id: trailing-whitespace\n",
        encoding="utf-8",
    )
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=False))
    text = (tmp_path / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "trailing-whitespace" in text
    assert "id: opentide-validate" in text
    assert ".pre-commit-config.yaml" in result["files"]


def test_run_hooks_setup_leaves_unparseable_config(tmp_path: Path) -> None:
    (tmp_path / ".pre-commit-config.yaml").write_text("- just a list\n", encoding="utf-8")
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=False))
    assert (tmp_path / ".pre-commit-config.yaml").read_text(encoding="utf-8") == "- just a list\n"
    assert "left unchanged" in result["warnings"][0]


def test_run_hooks_setup_leaves_invalid_yaml_config(tmp_path: Path) -> None:
    (tmp_path / ".pre-commit-config.yaml").write_text("{[\n", encoding="utf-8")
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=False))
    assert (tmp_path / ".pre-commit-config.yaml").read_text(encoding="utf-8") == "{[\n"
    assert "not valid YAML" in result["warnings"][0]


def test_setup_hooks_cli_json(tmp_path: Path) -> None:
    _git_init(tmp_path)
    result = runner.invoke(
        app,
        ["--json", "setup", "hooks", str(tmp_path), "--yes"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert (tmp_path / ".pre-commit-config.yaml").is_file()
    assert (tmp_path / ".git" / "hooks" / "pre-commit").is_file()
    assert '"ok": true' in result.stdout
    assert '"installed": true' in result.stdout


def test_setup_hooks_cli_requires_yes_without_tty(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--json", "setup", "hooks", str(tmp_path)])
    assert result.exit_code != 0
    assert not (tmp_path / ".pre-commit-config.yaml").exists()
    assert "--yes" in result.stdout


def test_nested_workspace_installs_into_the_enclosing_repository(tmp_path: Path) -> None:
    """``<workspace>/.git`` does not exist below the Git root; ask Git instead."""
    hooks_dir = _git_init(tmp_path)
    workspace = tmp_path / "security" / "detections"
    result = run_hooks_setup(HooksSetupOptions(path=workspace, yes=True, install=True))

    assert result["installed"] is True
    assert "../../.git/hooks/pre-commit" in result["files"]
    installed = (hooks_dir / "pre-commit").read_text(encoding="utf-8")
    assert installed == (workspace / ".opentide" / "hooks" / "pre-commit").read_text(
        encoding="utf-8"
    )
    assert 'OPENTIDE_HOOK_REPO="$OPENTIDE_HOOK_REPO"/security/detections' in installed
    config = (workspace / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert 'repo="$(git rev-parse --show-toplevel)"/security/detections;' in config
    assert any("repository root" in warning for warning in result["warnings"])


def test_nested_workspace_replaces_a_root_pinned_entry(tmp_path: Path) -> None:
    """The root-pinned entry validated the monorepo root, which has no objects."""
    _git_init(tmp_path)
    workspace = tmp_path / "detections"
    workspace.mkdir()
    config = workspace / ".pre-commit-config.yaml"
    config.write_text(
        f"repos:\n  - repo: local\n    hooks:\n      - id: opentide-validate\n        entry: {HOOK_ENTRY}\n",
        encoding="utf-8",
    )

    result = run_hooks_setup(HooksSetupOptions(path=workspace, yes=True, install=False))

    assert ".pre-commit-config.yaml" in result["files"]
    assert HOOK_ENTRY not in config.read_text(encoding="utf-8")
    assert _entry(config) == hook_entry("detections")


def _stub_opentide(tmp_path: Path) -> dict[str, str]:
    """An ``opentide`` that passes and records its ``--repo``, like ``validate`` on an empty tree."""
    bin_dir = tmp_path / "stub-bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "opentide"
    stub.write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$2" >> {shlex.quote(str(tmp_path / "validated.log"))}\n'
        'echo "OK Validation passed"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OPENTIDE_", "GIT_"))}
    return env | {"PATH": f"{bin_dir}{os.pathsep}{env['PATH']}"}


def _validated(tmp_path: Path) -> list[str]:
    log = tmp_path / "validated.log"
    return log.read_text(encoding="utf-8").splitlines() if log.is_file() else []


def _entry(config: Path) -> str:
    parsed = yaml.safe_load(config.read_text(encoding="utf-8"))
    return next(
        hook["entry"]
        for repo in parsed["repos"]
        for hook in repo["hooks"]
        if hook["id"] == "opentide-validate"
    )


@pytest.mark.parametrize("relative", ["", "renamed"])
def test_hook_script_fails_when_the_pinned_workspace_is_gone(tmp_path: Path, relative: str) -> None:
    """``validate --strict`` passes on a missing directory; the hook must not."""
    repo = tmp_path / "repo"
    _git_init(repo)
    hook = tmp_path / "pre-commit"
    hook.write_text(pre_commit_script(relative), encoding="utf-8")

    done = subprocess.run(
        ["sh", str(hook)], cwd=repo, env=_stub_opentide(tmp_path), capture_output=True, text=True
    )

    assert done.returncode == 1, done.stdout + done.stderr
    assert "No OpenTide workspace at" in done.stderr
    assert "opentide setup hooks" in done.stderr
    assert "OPENTIDE_SKIP_HOOKS=1" in done.stderr
    assert _validated(tmp_path) == []


@pytest.mark.parametrize("relative", ["", "renamed"])
def test_pre_commit_entry_fails_when_the_pinned_workspace_is_gone(
    tmp_path: Path, relative: str
) -> None:
    repo = tmp_path / "repo"
    _git_init(repo)

    done = subprocess.run(
        shlex.split(hook_entry(relative)),
        cwd=repo,
        env=_stub_opentide(tmp_path),
        capture_output=True,
        text=True,
    )

    assert done.returncode == 1, done.stdout + done.stderr
    assert "No OpenTide workspace at" in done.stderr
    assert "opentide setup hooks" in done.stderr
    assert _validated(tmp_path) == []


@pytest.mark.parametrize("relative", ["", "security/detections"])
def test_pre_commit_entry_validates_an_existing_workspace(tmp_path: Path, relative: str) -> None:
    repo = tmp_path / "repo"
    _git_init(repo)
    (repo / relative / ".opentide").mkdir(parents=True)

    done = subprocess.run(
        shlex.split(hook_entry(relative)),
        cwd=repo,
        env=_stub_opentide(tmp_path),
        capture_output=True,
        text=True,
    )

    assert done.returncode == 0, done.stdout + done.stderr
    assert _validated(tmp_path) == [str((repo / relative).resolve())]


@pytest.mark.parametrize("relative", ["", "detections"])
def test_setup_refreshes_an_entry_without_the_workspace_guard(
    tmp_path: Path, relative: str
) -> None:
    """The previous entry pinned the workspace but passed when it was gone."""
    _git_init(tmp_path)
    workspace = tmp_path / relative
    workspace.mkdir(exist_ok=True)
    pin = '"$(git rev-parse --show-toplevel)"' + (f"/{relative}" if relative else "")
    unguarded = "sh -c " + shlex.quote(f"opentide --repo {pin} validate --strict")
    config = workspace / ".pre-commit-config.yaml"
    config.write_text(
        "repos:\n  - repo: local\n    hooks:\n      - id: opentide-validate\n"
        f"        entry: {unguarded}\n        language: system\n",
        encoding="utf-8",
    )

    result = run_hooks_setup(HooksSetupOptions(path=workspace, yes=True, install=False))

    assert ".pre-commit-config.yaml" in result["files"]
    assert _entry(config) == hook_entry(relative)
    assert "language: system" in config.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "value",
    [
        "a: b",
        "a #b",
        "a\t#b",
        "a\nb",
        "a\tb",
        "&anchor",
        "*alias",
        "- item",
        "!tag",
        "%directive",
        "@at",
        "`tick",
        "'quoted",
        '"quoted',
        "{flow}",
        "[flow]",
        "|block",
        ">folded",
        "? key",
        "trailing:",
        "true",
        "1",
    ],
)
def test_yaml_value_round_trips(value: str) -> None:
    """Tab before ``#`` and newlines produced invalid or truncated YAML."""
    rendered = _yaml_value(value)
    assert rendered != value
    assert yaml.safe_load(f"hooks:\n  - entry: {rendered}\n") == {"hooks": [{"entry": value}]}


def test_yaml_value_keeps_plain_commands_plain() -> None:
    assert _yaml_value("opentide validate --strict") == "opentide validate --strict"
    assert _yaml_value(HOOK_ENTRY) == HOOK_ENTRY


def test_linked_worktree_installs_the_shared_hook(tmp_path: Path) -> None:
    """A linked worktree has a ``.git`` *file*; its hooks live in the common directory."""
    main = tmp_path / "main"
    hooks_dir = _git_init(main)
    git = ["git", "-C", str(main), "-c", "user.name=t", "-c", "user.email=t@example.test"]
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "seed"], check=True)
    linked = tmp_path / "linked"
    subprocess.run([*git, "worktree", "add", "-q", str(linked)], check=True)
    assert (linked / ".git").is_file()

    result = run_hooks_setup(HooksSetupOptions(path=linked, yes=True, install=True))

    assert result["installed"] is True, result
    assert HOOK_MARKER in (hooks_dir / "pre-commit").read_text(encoding="utf-8")
