"""Tests for CI platform discovery."""

from __future__ import annotations

from pathlib import Path

from opentide.ci.discovery import discover_enabled_platforms, platforms_config_dir


def test_discover_enabled_platforms_empty_when_missing(tmp_path: Path) -> None:
    assert discover_enabled_platforms(tmp_path) == []


def test_discover_enabled_platforms_reads_enabled_toml(tmp_path: Path) -> None:
    config_dir = platforms_config_dir(tmp_path)
    config_dir.mkdir(parents=True)
    (config_dir / "sentinel.toml").write_text(
        "[platform]\nenabled = true\n",
        encoding="utf-8",
    )
    (config_dir / "splunk.toml").write_text(
        "[platform]\nenabled = false\n",
        encoding="utf-8",
    )
    (config_dir / "crowdstrike.toml").write_text(
        'name = "crowdstrike"\n',
        encoding="utf-8",
    )
    assert discover_enabled_platforms(tmp_path) == ["sentinel"]
