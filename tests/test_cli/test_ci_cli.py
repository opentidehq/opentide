"""CLI tests for opentide setup ci."""

from __future__ import annotations

from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()


def test_setup_ci_github(tmp_path) -> None:
    platforms_dir = tmp_path / ".opentide" / "configurations" / "platforms"
    platforms_dir.mkdir(parents=True)
    (platforms_dir / "sentinel.toml").write_text("[platform]\nenabled = true\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "--json",
            "setup",
            "ci",
            "github",
            "--path",
            str(tmp_path),
            "--no-promotion",
            "--yes",
        ],
    )
    assert result.exit_code == 0
    assert '"files"' in result.stdout
    workflow = tmp_path / ".github" / "workflows" / "opentide.yml"
    assert workflow.is_file()
    text = workflow.read_text(encoding="utf-8")
    assert "opentide validate" in text
    assert "validate query" in text
    assert "sentinel" in text
    assert "OPENTIDE_REPO_ROOT: ${{ github.workspace }}" in text
    assert "mutate promote" not in text


def test_setup_ci_rejects_none_platform() -> None:
    result = runner.invoke(app, ["setup", "ci", "none"])
    assert result.exit_code != 0
