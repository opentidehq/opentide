"""Discover enabled platforms from repository configuration."""

from __future__ import annotations

import re
from pathlib import Path

from opentide.registry.discovery import OPENTIDE_DIR

_PLATFORM_SECTION = re.compile(r"^\[platform\]\s*$", re.MULTILINE)
_ENABLED = re.compile(r"^enabled\s*=\s*true\s*$", re.MULTILINE | re.IGNORECASE)


def platforms_config_dir(repo: Path) -> Path:
    return repo / OPENTIDE_DIR / "configurations" / "platforms"


def discover_enabled_platforms(repo: Path) -> list[str]:
    """Return platform identifiers with ``enabled = true`` in platform TOML files."""
    config_dir = platforms_config_dir(repo)
    if not config_dir.is_dir():
        return []
    enabled: list[str] = []
    for path in sorted(config_dir.glob("*.toml")):
        text = path.read_text(encoding="utf-8")
        if not _PLATFORM_SECTION.search(text):
            continue
        if not _ENABLED.search(text):
            continue
        enabled.append(path.stem)
    return enabled
