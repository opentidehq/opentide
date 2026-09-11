"""CLI smoke tests for opentide setup."""

from __future__ import annotations

import importlib
import json

from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.setup.skills import SkillsDownloadError

runner = CliRunner()


def test_setup_help_lists_subcommands() -> None:
    result = runner.invoke(app, ["setup", "--help"])
    assert result.exit_code == 0
    assert "repo" in result.stdout
    assert "mcp" in result.stdout
    assert "skills" in result.stdout


def test_setup_without_tty_fails_with_scripted_guidance(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["--json", "--repo", str(tmp_path), "setup"],
    )
    assert result.exit_code == 1
    assert '"ok": false' in result.stdout
    assert "--yes" in result.stdout


def test_setup_repo_scripted(tmp_path) -> None:
    result = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "repo",
            str(tmp_path),
            "--yes",
            "--name",
            "CLI Test",
        ],
    )
    assert result.exit_code == 0
    assert (tmp_path / "README.md").is_file()


def test_setup_mcp_vscode(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "mcp", str(tmp_path), "--yes", "--vscode"],
    )
    assert result.exit_code == 0
    assert (tmp_path / ".vscode" / "mcp.json").is_file()


def test_setup_mcp_yes_requires_explicit_host(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "mcp", str(tmp_path), "--yes"],
    )
    assert result.exit_code == 2
    assert not (tmp_path / ".vscode" / "mcp.json").exists()


def test_setup_skills_help_does_not_bind_positional_path() -> None:
    result = runner.invoke(app, ["setup", "skills", "--help"])
    assert result.exit_code == 0
    assert "discover" in result.stdout
    assert "show" in result.stdout
    assert "[PATH] COMMAND" not in result.stdout


def test_setup_skills_discover_is_subcommand_not_path(tmp_path, monkeypatch) -> None:
    from opentide.cli.services.setup import skills_registry as registry

    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    registry.clear_manifest_cache()
    result = runner.invoke(
        app,
        ["--json", "setup", "skills", "discover", "--path", str(tmp_path)],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "DEPRECATED" not in result.output
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["count"] >= 1
    slugs = {item["slug"] for item in payload["skills"]}
    assert "opentide-detection-rule" in slugs
    assert "detection-engineering" in slugs


def test_setup_skills_show_is_subcommand(tmp_path, monkeypatch) -> None:
    from opentide.cli.services.setup import skills_registry as registry

    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    registry.clear_manifest_cache()
    result = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "skills",
            "show",
            "opentide-detection-rule",
            "--path",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "DEPRECATED" not in result.output
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["skill"]["slug"] == "opentide-detection-rule"


def test_setup_skills_yes_requires_explicit_target(tmp_path, mock_skill_download) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "skills", "--yes", "--path", str(tmp_path)],
    )
    assert result.exit_code == 2
    assert not (tmp_path / "AGENTS.md").exists()


def test_setup_skills_download_failure_is_normalized_json(tmp_path, monkeypatch) -> None:
    def fail_download(options: object) -> None:
        raise SkillsDownloadError("network unavailable")

    setup_module = importlib.import_module("opentide.cli.setup_app")
    monkeypatch.setattr(setup_module, "run_skills_setup", fail_download)
    result = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "skills",
            "--generic",
            "--yes",
            "--path",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 1
    assert '"ok": false' in result.stdout
    assert "network unavailable" in result.stdout


def test_setup_vscode_settings_command(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "vscode", str(tmp_path), "--settings"],
    )
    assert result.exit_code == 0
    assert (tmp_path / ".vscode" / "settings.json").is_file()


def test_setup_vscode_snippets_command_skips_without_templates(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "vscode", str(tmp_path), "--snippets"],
    )
    assert result.exit_code == 0
    assert '"files": []' in result.stdout


def test_setup_ci_none_alone_is_not_noop(tmp_path, monkeypatch) -> None:
    """Only --ci none should not silently succeed with zero steps."""
    import importlib

    setup_module = importlib.import_module("opentide.cli.setup_app")
    monkeypatch.setattr(
        setup_module,
        "run_interactive_setup",
        lambda cli, base: {"message": "interactive", "path": str(base)},
    )
    result = runner.invoke(
        app,
        ["--json", "setup", "--path", str(tmp_path), "--ci", "none"],
    )
    assert result.exit_code == 0
    assert "interactive" in result.stdout


def test_validate_scope_flags_do_not_raise_type_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.validation.run_validate_all",
        lambda: {"schema": {"status": "passed"}},
    )
    monkeypatch.setattr("opentide.cli.exit_codes.exit_on_validation_errors", lambda: None)
    result = runner.invoke(app, ["--json", "validate", "--file", "Objects/foo.yaml"])
    assert "TypeError" not in (result.stdout + result.stderr)
    assert '"checks"' in result.stdout
