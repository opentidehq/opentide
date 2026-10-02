"""CLI smoke tests for opentide setup."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

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
    assert "env" in result.stdout
    assert "hooks" in result.stdout


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


def test_setup_repo_platform_writes_enabled_toml(tmp_path) -> None:
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
            "--platform",
            "sentinel",
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    toml_path = tmp_path / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    assert toml_path.is_file()
    assert "enabled = true" in toml_path.read_text(encoding="utf-8")


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
    from tests.test_cli.conftest import stub_remote_skills_manifest

    stub_remote_skills_manifest(monkeypatch)
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
    assert payload["manifest_source"] == "remote"


def test_setup_skills_discover_fails_when_catalogue_unavailable(tmp_path, monkeypatch) -> None:
    from opentide.cli.services.setup import skills_registry as registry

    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    registry.clear_manifest_cache()
    result = runner.invoke(
        app,
        ["--json", "setup", "skills", "discover", "--path", str(tmp_path)],
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "OpenTideHQ/skills" in payload["error"]


def test_setup_skills_install_fails_when_catalogue_unavailable(tmp_path, monkeypatch) -> None:
    from opentide.cli.services.setup import skills_registry as registry

    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    registry.clear_manifest_cache()
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
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "OpenTideHQ/skills" in payload["error"]
    assert not (tmp_path / ".agents").exists()


def test_setup_skills_discover_human_table(tmp_path, monkeypatch) -> None:
    from tests.test_cli.conftest import stub_remote_skills_manifest

    stub_remote_skills_manifest(monkeypatch)
    result = runner.invoke(
        app,
        ["setup", "skills", "discover", "--path", str(tmp_path)],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    combined = result.stdout + result.stderr
    assert "opentide-detection-rule" in combined or "OpenTide Skills" in combined
    assert "DEPRECATED" not in combined


def test_setup_skills_discover_positional_path_is_deprecated(tmp_path, monkeypatch) -> None:
    from tests.test_cli.conftest import stub_remote_skills_manifest

    stub_remote_skills_manifest(monkeypatch)
    human = runner.invoke(app, ["setup", "skills", "discover", str(tmp_path)])
    assert human.exit_code == 0, human.stdout + human.stderr
    assert "DEPRECATED" in human.output
    assert "--path/-C" in human.output

    machine = runner.invoke(
        app,
        ["--json", "setup", "skills", "discover", str(tmp_path)],
    )
    assert machine.exit_code == 0, machine.stdout + machine.stderr
    assert "DEPRECATED" not in machine.output
    assert "cli_command_deprecated" in machine.stderr


def test_setup_skills_show_is_subcommand(tmp_path, monkeypatch) -> None:
    from tests.test_cli.conftest import stub_remote_skills_manifest

    stub_remote_skills_manifest(monkeypatch)
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


def test_setup_skills_show_human_and_missing(tmp_path, monkeypatch) -> None:
    from tests.test_cli.conftest import stub_remote_skills_manifest

    stub_remote_skills_manifest(monkeypatch)
    found = runner.invoke(
        app,
        [
            "setup",
            "skills",
            "show",
            "opentide-detection-rule",
            "--path",
            str(tmp_path),
        ],
    )
    assert found.exit_code == 0, found.stdout + found.stderr
    assert "opentide-detection-rule" in found.stdout
    assert "install" in found.stdout.lower()

    missing = runner.invoke(
        app,
        ["setup", "skills", "show", "no-such-skill-xyz", "--path", str(tmp_path)],
    )
    assert missing.exit_code == 1
    assert "skill not found" in (missing.stdout + missing.stderr).lower()

    missing_json = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "skills",
            "show",
            "no-such-skill-xyz",
            "--path",
            str(tmp_path),
        ],
    )
    assert missing_json.exit_code == 1
    payload = json.loads(missing_json.stdout)
    assert payload["ok"] is False
    assert "error" in payload


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


def test_setup_vscode_mcp_flag_writes_mcp_json(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "vscode", str(tmp_path), "--settings", "--mcp", "--no-generate"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert (tmp_path / ".vscode" / "mcp.json").is_file()
    assert (tmp_path / ".vscode" / "settings.json").is_file()


def test_setup_vscode_snippets_command_fails_without_templates(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "vscode", str(tmp_path), "--snippets", "--no-generate"],
    )
    assert result.exit_code != 0
    assert '"status": "failed"' in result.stdout
    assert '"ok": false' in result.stdout
    assert '"files": []' in result.stdout


def test_setup_yes_ci_none_still_scaffolds(tmp_path: Path) -> None:
    """#349: ``--yes --ci none`` exited 0 with ``steps: []`` and wrote nothing."""
    result = runner.invoke(
        app,
        ["--json", "setup", "--yes", "--ci", "none", "--path", str(tmp_path)],
        env={"OPENTIDE_REPO_ROOT": None, "OPENTIDE_TIDE_WORKSPACE": None},
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["message"] == "Setup complete"
    assert any(step["step"] == "repo" for step in payload["steps"])
    assert (tmp_path / "README.md").is_file()
    assert not (tmp_path / ".github" / "workflows" / "opentide.yml").exists()
    assert not (tmp_path / ".gitlab-ci.yml").exists()
    assert not (tmp_path / "azure-pipelines.yml").exists()
    assert payload.get("warnings", []) == []


def test_ci_only_flags_without_a_platform_are_named(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "--yes",
            "--path",
            str(tmp_path),
            "--no-staging",
            "--no-inflight",
            "--explorer-pages",
            "--default-branch",
            "trunk",
            "--python-version",
            "3.11",
        ],
        env={"OPENTIDE_REPO_ROOT": None, "OPENTIDE_TIDE_WORKSPACE": None},
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    warning = " ".join(payload["warnings"])
    for flag in (
        "--default-branch",
        "--no-staging",
        "--no-inflight",
        "--explorer-pages",
        "--python-version",
    ):
        assert flag in warning
    assert (tmp_path / "README.md").is_file()
    assert not (tmp_path / ".github" / "workflows" / "opentide.yml").exists()


def test_sharing_without_a_platform_warns_and_writes_no_pipeline(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--json", "setup", "--yes", "--sharing", "--ci", "none", "--path", str(tmp_path)],
        env={"OPENTIDE_REPO_ROOT": None, "OPENTIDE_TIDE_WORKSPACE": None},
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    warning = " ".join(payload.get("warnings", []))
    assert "--sharing" in warning
    assert (tmp_path / "README.md").is_file()
    assert not (tmp_path / ".github" / "workflows" / "opentide.yml").exists()


def test_setup_ci_sharing_writes_and_can_remove_the_share_job(tmp_path: Path) -> None:
    env = {"OPENTIDE_REPO_ROOT": None, "OPENTIDE_TIDE_WORKSPACE": None}
    written = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "ci",
            "github",
            "--yes",
            "--sharing",
            "--default-branch",
            "main",
            "--path",
            str(tmp_path),
        ],
        env=env,
    )
    assert written.exit_code == 0, written.stdout + written.stderr
    workflow = tmp_path / ".github" / "workflows" / "opentide.yml"
    rendered = workflow.read_text(encoding="utf-8")
    assert rendered.count("opentide share push --changed") == 1
    removed = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "ci",
            "github",
            "--yes",
            "--no-sharing",
            "--default-branch",
            "main",
            "--path",
            str(tmp_path),
        ],
        env=env,
    )
    assert removed.exit_code == 0, removed.stdout + removed.stderr
    assert "opentide share" not in workflow.read_text(encoding="utf-8")


def test_setup_ci_help_does_not_offer_none() -> None:
    result = runner.invoke(app, ["setup", "ci", "--help"])
    assert result.exit_code == 0, result.stdout
    arguments = result.stdout.split("Arguments", 1)[1].split("Options", 1)[0]
    assert "none" not in arguments
    assert "github" in arguments
    assert "gitlab" in arguments
    assert "azure" in arguments


def test_setup_ci_none_is_rejected(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["setup", "ci", "none", "--yes", "--path", str(tmp_path)],
    )
    assert result.exit_code == 2
    assert "Choose github, gitlab, or azure" in result.stdout + result.stderr
    assert not (tmp_path / ".github").exists()


def test_json_setup_quotes_a_dot_target(tmp_path: Path, monkeypatch) -> None:
    """#346: ``Path('.')`` plus the sentence period rendered the target as ``..``."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["--json", "setup", "--platform", "sentinel"],
        env={"OPENTIDE_REPO_ROOT": None, "OPENTIDE_TIDE_WORKSPACE": None},
    )
    assert result.exit_code != 0, result.stdout + result.stderr
    assert "write to '.'" in result.stdout
    assert "write to .." not in result.stdout
    absolute = tmp_path / "empty"
    named = runner.invoke(
        app,
        ["--json", "setup", "--path", str(absolute), "--platform", "sentinel"],
        env={"OPENTIDE_REPO_ROOT": None, "OPENTIDE_TIDE_WORKSPACE": None},
    )
    assert named.exit_code != 0
    assert f"write to '{absolute.as_posix()}'" in named.stdout


def test_setup_ci_none_alone_is_not_noop(tmp_path, monkeypatch) -> None:
    """Only --ci none should not silently succeed with zero steps."""
    setup_module = importlib.import_module("opentide.cli.setup_app")
    monkeypatch.setattr(
        setup_module,
        "run_interactive_setup",
        lambda cli, base: {"message": "interactive", "path": str(base)},
    )
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path), "--ci", "none"],
    )
    assert result.exit_code == 0, result.stdout
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
