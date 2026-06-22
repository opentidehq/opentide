"""Paths to bundled schema, definition, and subschema data."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from opentide.core.root import get_data_root


def schemas_data_root() -> Path:
    """Root directory for code-first schema assets."""
    bundled = Path(__file__).resolve().parent / "data"
    if bundled.is_dir():
        return bundled
    return get_data_root() / "schemas"


def metaschemas_path() -> Path:
    return schemas_data_root()


def subschemas_path() -> Path:
    return schemas_data_root() / "Sub Schemas"


def definitions_path() -> Path:
    return schemas_data_root() / "Definitions"


def vocabulary_root() -> Path:
    """Bundled vocabulary YAML directory."""
    return get_data_root() / "vocabulary"


def external_root() -> Path:
    """Bundled external reference data directory."""
    return get_data_root() / "external"


def platform_configs_root() -> Path:
    """Bundled per-platform TOML defaults."""
    return get_data_root() / "configurations" / "platforms"


def bundled_data_exists() -> bool:
    """Return whether importlib can resolve the ``opentide.data`` package."""
    try:
        files("opentide.data")
        return True
    except (ModuleNotFoundError, TypeError):
        return False
