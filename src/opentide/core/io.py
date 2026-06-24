"""Shared file I/O helpers for YAML, JSON, and TOML."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import toml
import yaml

from opentide.core.files import IndentFullDumper


def load_yaml(path: Path) -> Any:
    """Load YAML from *path*."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_json(path: Path) -> Any:
    """Load JSON from *path*."""
    return json.loads(path.read_text(encoding="utf-8"))


def load_toml(path: Path) -> dict[str, Any]:
    """Load TOML from *path*."""
    return toml.loads(path.read_text(encoding="utf-8"))


def dump_yaml(
    path: Path,
    data: Mapping[str, Any],
    *,
    dumper: type[yaml.Dumper] = IndentFullDumper,
) -> None:
    """Write *data* as YAML to *path*, creating parent directories."""
    write_text(path, yaml.dump(dict(data), Dumper=dumper, sort_keys=False))


def write_text(path: Path, content: str) -> None:
    """Write UTF-8 text to *path*, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
