"""Tests for migrate scanner and rewriter."""

from __future__ import annotations

from pathlib import Path

from opentide.cli.migrate import apply_migrations, scan_repo


def test_scan_detects_orchestration_and_coretide_ci(tmp_path: Path) -> None:
    gitlab = tmp_path / ".gitlab-ci.yml"
    gitlab.write_text(
        "include:\n"
        "  - remote: 'https://raw.githubusercontent.com/OpenTideHQ/CoreTide/development/x.yml'\n"
        "script:\n"
        "  - cd $TIDE_CORE_REPO/Orchestration/\n",
        encoding="utf-8",
    )
    azure = tmp_path / "azure-pipelines.yml"
    azure.write_text("- template: coretide_initialization.yml\n", encoding="utf-8")

    findings = scan_repo(tmp_path)
    files = {item["file"] for item in findings}
    assert ".gitlab-ci.yml" in files
    assert "azure-pipelines.yml" in files
    assert any(
        "gitlab" in item["suggestion"] for item in findings if item["file"] == ".gitlab-ci.yml"
    )
    assert any(
        "azure" in item["suggestion"] for item in findings if item["file"] == "azure-pipelines.yml"
    )


def test_apply_migrations_rewrites_orchestration_calls(tmp_path: Path) -> None:
    script = tmp_path / "run.sh"
    script.write_text("python Orchestration/validate.py\n", encoding="utf-8")
    changed = apply_migrations(tmp_path)
    assert changed == ["run.sh"]
    assert script.read_text(encoding="utf-8") == "opentide validate\n"
