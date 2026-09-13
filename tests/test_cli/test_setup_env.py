"""Tests for ``opentide setup env``."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.setup.env import EnvSetupOptions, run_env_setup

runner = CliRunner()


def test_run_env_setup_writes_example_and_gitignore(tmp_path: Path) -> None:
    result = run_env_setup(EnvSetupOptions(path=tmp_path, yes=True))
    example = tmp_path / ".env.example"
    gitignore = tmp_path / ".gitignore"
    assert example.is_file()
    text = example.read_text(encoding="utf-8")
    assert "OPENTIDE_REPO_ROOT=." in text
    assert "# OpenTide" in text
    assert gitignore.is_file()
    assert ".env\n" in gitignore.read_text(encoding="utf-8")
    assert ".env.example" not in gitignore.read_text(encoding="utf-8")
    assert result["files"] == [".env.example", ".gitignore"]
    assert result["skipped"] == []
    assert result["message"] == "Environment example written"


def test_run_env_setup_is_idempotent(tmp_path: Path) -> None:
    run_env_setup(EnvSetupOptions(path=tmp_path, yes=True))
    first = (tmp_path / ".env.example").read_text(encoding="utf-8")
    second = run_env_setup(EnvSetupOptions(path=tmp_path, yes=True))
    assert (tmp_path / ".env.example").read_text(encoding="utf-8") == first
    assert second["files"] == []
    assert second["skipped"] == [".env.example", ".gitignore"]
    assert second["message"] == "Environment example already present"


def test_run_env_setup_appends_missing_repo_root(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("DEBUG=1", encoding="utf-8")
    result = run_env_setup(EnvSetupOptions(path=tmp_path, yes=True))
    text = (tmp_path / ".env.example").read_text(encoding="utf-8")
    assert text.endswith("OPENTIDE_REPO_ROOT=.\n")
    assert text.startswith("DEBUG=1\n")
    assert ".env.example" in result["files"]


def test_run_env_setup_preserves_custom_repo_root(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("OPENTIDE_REPO_ROOT=/custom\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    result = run_env_setup(EnvSetupOptions(path=tmp_path, yes=True))
    assert (tmp_path / ".env.example").read_text(encoding="utf-8") == "OPENTIDE_REPO_ROOT=/custom\n"
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8") == ".venv/\n.env\n"
    assert result["files"] == [".gitignore"]
    assert ".env.example" in result["skipped"]


def test_run_env_setup_does_not_duplicate_gitignore_env(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n.venv/\n", encoding="utf-8")
    result = run_env_setup(EnvSetupOptions(path=tmp_path, yes=True))
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8") == ".env\n.venv/\n"
    assert ".gitignore" in result["skipped"]


def test_setup_env_cli_json(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "env", str(tmp_path), "--yes"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert (tmp_path / ".env.example").is_file()
    assert '"ok": true' in result.stdout
    assert ".env.example" in result.stdout


def test_setup_env_cli_requires_yes_without_tty(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "env", str(tmp_path)],
    )
    assert result.exit_code != 0
    assert not (tmp_path / ".env.example").exists()
    assert "--yes" in result.stdout
