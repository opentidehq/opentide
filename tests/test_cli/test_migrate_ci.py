"""Tests for legacy CI migration detection."""

from __future__ import annotations

from pathlib import Path

from opentide.cli.migrate import scan_repo


def test_scan_detects_coretide_ci_patterns(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "legacy.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "uses: ./coretide/Pipelines/GitHub/deployment\nrepository: OpenTideHQ/CoreTide\n",
        encoding="utf-8",
    )
    findings = scan_repo(tmp_path)
    patterns = {item["pattern"] for item in findings}
    assert "OpenTideHQ/CoreTide" in patterns
    assert "Pipelines/GitHub/" in patterns
    assert any("opentide ci generate --ci github" in item["suggestion"] for item in findings)
