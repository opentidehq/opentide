"""CLI tests for opentide ci generate."""

from __future__ import annotations

from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()


def test_ci_generate_github(tmp_path) -> None:
    result = runner.invoke(
        app,
        [
            "--json",
            "ci",
            "generate",
            str(tmp_path),
            "--ci",
            "github",
            "--platform",
            "sentinel",
            "--no-promotion",
        ],
    )
    assert result.exit_code == 0
    assert '"files"' in result.stdout
    workflow = tmp_path / ".github" / "workflows" / "opentide.yml"
    assert workflow.is_file()
    text = workflow.read_text(encoding="utf-8")
    assert "opentide validate" in text
    assert "mutate promote" not in text


def test_ci_generate_rejects_none_platform() -> None:
    result = runner.invoke(app, ["ci", "generate", "--ci", "none"])
    assert result.exit_code != 0
