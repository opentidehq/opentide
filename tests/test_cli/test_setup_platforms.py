"""Tests for setup platforms command module."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.platforms import PlatformsSetupOptions, run_platforms_setup


def test_run_platforms_setup_writes_enabled_toml(tmp_path: Path) -> None:
    result = run_platforms_setup(
        PlatformsSetupOptions(path=tmp_path, platforms=[DetectionPlatform.sentinel], yes=True)
    )
    out = tmp_path / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    assert out.is_file()
    assert "enabled = true" in out.read_text(encoding="utf-8")
    assert result["message"] == "Platform configuration files created"


def test_run_platforms_setup_requires_platform() -> None:
    with pytest.raises(ValueError, match="Choose at least one platform"):
        run_platforms_setup(PlatformsSetupOptions(platforms=[]))
