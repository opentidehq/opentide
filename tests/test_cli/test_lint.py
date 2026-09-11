"""Tests for ``opentide lint``."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import LintCheck
from opentide.cli.services.lint import run_lint

runner = CliRunner()

_THREAT = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
  author: SOC
  organisation: Example
"""


def _write_object(root: Path, family: str, filename: str, body: str) -> Path:
    dest = root / "objects" / family / filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(body, encoding="utf-8")
    return dest


def test_lint_passes_matching_slug(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "simulated-actor.yaml", _THREAT)
    result = run_lint(tmp_path)
    assert result["count"] == 0
    assert result["_exit_code"] == 0


def test_lint_reports_filename_mismatch(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = run_lint(tmp_path, checks=[LintCheck.filenames])
    assert result["count"] == 1
    finding = result["findings"][0]
    assert finding["expected"] == "objects/threats/simulated-actor.yaml"
    assert result["_exit_code"] == 0


def test_lint_strict_fails_on_findings(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = run_lint(tmp_path, checks=[LintCheck.filenames], strict=True)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1


def test_lint_fix_renames_file(tmp_path: Path) -> None:
    src = _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    assert result["fixed"] == 1
    assert not src.exists()
    dest = tmp_path / "objects" / "threats" / "simulated-actor.yaml"
    assert dest.is_file()
    second = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    assert second["count"] == 0


def test_lint_fix_collision_uses_uuid_suffix(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "simulated-actor.yaml", _THREAT)
    other = """\
name: Simulated Actor
metadata:
  uuid: 11111111-1111-4111-8111-111111111111
  schema: threat::1.0
"""
    _write_object(tmp_path, "threats", "other.yaml", other)
    result = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    assert (tmp_path / "objects" / "threats" / "simulated-actor.yaml").is_file()
    assert (tmp_path / "objects" / "threats" / "simulated-actor-11111111.yaml").is_file()
    assert result["fixed"] == 1


def test_lint_metadata_missing(tmp_path: Path) -> None:
    body = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
"""
    _write_object(tmp_path, "threats", "simulated-actor.yaml", body)
    result = run_lint(tmp_path, checks=[LintCheck.metadata])
    assert result["count"] == 1
    assert "author" in result["findings"][0]["message"]
    assert "organisation" in result["findings"][0]["message"]


def test_lint_check_filenames_skips_metadata(tmp_path: Path) -> None:
    body = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
"""
    _write_object(tmp_path, "threats", "simulated-actor.yaml", body)
    result = run_lint(tmp_path, checks=[LintCheck.filenames])
    assert result["count"] == 0


def test_lint_cli_json(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = runner.invoke(
        app,
        ["--json", "--repo", str(tmp_path), "lint", "--check", "filenames"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert '"count": 1' in result.stdout


def test_lint_cli_strict(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = runner.invoke(
        app,
        ["--json", "--repo", str(tmp_path), "lint", "--check", "filenames", "--strict"],
    )
    assert result.exit_code == 1
    assert '"ok": false' in result.stdout
