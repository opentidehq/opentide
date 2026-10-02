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


def test_run_platforms_setup_keeps_comments_in_an_existing_file(tmp_path: Path) -> None:
    """#350: a second ``setup platforms`` replaced the file and dropped comments."""
    dest = tmp_path / ".opentide" / "configurations" / "platforms"
    dest.mkdir(parents=True)
    existing = dest / "sentinel.toml"
    existing.write_text(
        "# tenant note\n[platform]\nenabled = false\n# keep this\n",
        encoding="utf-8",
    )
    result = run_platforms_setup(
        PlatformsSetupOptions(path=tmp_path, platforms=[DetectionPlatform.sentinel], yes=True)
    )
    text = existing.read_text(encoding="utf-8")
    assert "# tenant note" in text
    assert "# keep this" in text
    assert "enabled = true" in text
    assert result["message"] == "Platform enabled flags updated"
    assert result["updated"] == [".opentide/configurations/platforms/sentinel.toml"]
    again = run_platforms_setup(
        PlatformsSetupOptions(path=tmp_path, platforms=[DetectionPlatform.sentinel], yes=True)
    )
    assert again["message"] == "Platform configuration files already present"
    assert existing.read_text(encoding="utf-8") == text


def test_run_platforms_setup_requires_platform() -> None:
    with pytest.raises(ValueError, match="Choose at least one platform"):
        run_platforms_setup(PlatformsSetupOptions(platforms=[]))
