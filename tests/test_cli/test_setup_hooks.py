"""Tests for ``opentide setup hooks``."""

from __future__ import annotations

import os
from pathlib import Path

from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.setup.hooks import (
    HOOK_MARKER,
    HooksSetupOptions,
    run_hooks_setup,
)

runner = CliRunner()


def test_run_hooks_setup_writes_config_and_versioned_hook(tmp_path: Path) -> None:
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    config = tmp_path / ".pre-commit-config.yaml"
    hook = tmp_path / ".opentide" / "hooks" / "pre-commit"
    assert config.is_file()
    text = config.read_text(encoding="utf-8")
    assert "id: opentide-validate" in text
    assert "opentide validate --strict" in text
    assert hook.is_file()
    script = hook.read_text(encoding="utf-8")
    assert HOOK_MARKER in script
    assert "opentide validate --strict" in script
    assert os.access(hook, os.X_OK)
    assert result["installed"] is False
    assert "Not a Git repository" in result["warnings"][0]
    assert ".pre-commit-config.yaml" in result["files"]
    assert ".opentide/hooks/pre-commit" in result["files"]


def test_run_hooks_setup_installs_git_hook(tmp_path: Path) -> None:
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    git_hook = tmp_path / ".git" / "hooks" / "pre-commit"
    assert git_hook.is_file()
    assert HOOK_MARKER in git_hook.read_text(encoding="utf-8")
    assert os.access(git_hook, os.X_OK)
    assert result["installed"] is True
    assert ".git/hooks/pre-commit" in result["files"]
    assert "warnings" not in result


def test_run_hooks_setup_does_not_clobber_foreign_git_hook(tmp_path: Path) -> None:
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    foreign = hooks_dir / "pre-commit"
    foreign.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
    assert result["installed"] is False
    assert "left unchanged" in result["warnings"][0]
    assert (tmp_path / ".opentide" / "hooks" / "pre-commit").is_file()


def test_run_hooks_setup_refreshes_managed_git_hook(tmp_path: Path) -> None:
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "pre-commit").write_text(
        f"#!/bin/sh\n# {HOOK_MARKER}\necho stale\n",
        encoding="utf-8",
    )
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=True))
    text = (tmp_path / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert "opentide validate --strict" in text
    assert "echo stale" not in text
    assert result["installed"] is True


def test_run_hooks_setup_no_install_skips_git_hook(tmp_path: Path) -> None:
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    result = run_hooks_setup(HooksSetupOptions(path=tmp_path, yes=True, install=False))
    assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()
    assert result["installed"] is False
    assert (tmp_path / ".pre-commit-config.yaml").is_file()


def test_run_hooks_setup_is_idempotent(tmp_path: Path) -> None:
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
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
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
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
