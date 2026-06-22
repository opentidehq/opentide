"""Tests for init scaffolding."""

from __future__ import annotations

from pathlib import Path

from opentide.cli.enums import CiPlatform, DetectionPlatform
from opentide.cli.services.init import InitOptions, run_init


def test_init_creates_scaffold(tmp_path: Path) -> None:
    target = tmp_path / "my-detections"
    options = InitOptions(
        path=target,
        name="SOC Detections",
        org="Security Operations",
        platforms=[DetectionPlatform.sentinel, DetectionPlatform.defender],
        ci=CiPlatform.github,
        yes=True,
    )
    result = run_init(options)
    assert target.is_dir()
    assert (target / "README.md").is_file()
    assert (target / "Objects" / "Detection Rules").is_dir()
    assert result["path"] == str(target.resolve())
    assert "sentinel" in result["platforms"]
