"""Migration scan tests."""

from __future__ import annotations

from pathlib import Path

from opentide.cli.migrate import scan_repo


def test_scan_finds_orchestration_references(tmp_path: Path) -> None:
    sample = tmp_path / "ci.yml"
    sample.write_text("run: python Orchestration/validate.py\n", encoding="utf-8")
    findings = scan_repo(tmp_path)
    assert any("Orchestration/validate" in f["pattern"] for f in findings)
