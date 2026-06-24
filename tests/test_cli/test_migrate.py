"""CLI migrate helper coverage."""

from __future__ import annotations

from pathlib import Path

from opentide.cli import migrate


def test_ci_suggestion_by_filename() -> None:
    assert "gitlab" in migrate._ci_suggestion(Path(".gitlab-ci.yml"))
    assert "azure" in migrate._ci_suggestion(Path("azure-pipelines.yml"))
    assert "github" in migrate._ci_suggestion(Path(".github/workflows/ci.yml"))


def test_scan_repo_finds_legacy_import(tmp_path: Path) -> None:
    script = tmp_path / "legacy.py"
    script.write_text("from Engines.modules.tide import DataTide\n", encoding="utf-8")
    findings = migrate.scan_repo(tmp_path)
    assert any("Engines" in item["pattern"] for item in findings)


def test_apply_migrations_rewrites_file(tmp_path: Path) -> None:
    script = tmp_path / "legacy.py"
    script.write_text("from Engines.modules.tide import OpenTide\n", encoding="utf-8")
    changed = migrate.apply_migrations(tmp_path)
    assert "legacy.py" in changed
    assert "from opentide import OpenTide" in script.read_text(encoding="utf-8")
