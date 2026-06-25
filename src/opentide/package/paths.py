"""Package-internal bundled asset paths (not client workspace paths)."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def _schemas_data_root() -> Path:
    return Path(str(files("opentide.schemas"))) / "data"


def recomposition_platforms_root() -> Path:
    """Bundled platform recomposition templates shipped with the package."""
    return _schemas_data_root() / "platform_templates"


def vocabulary_schema_path() -> Path:
    """Bundled vocabulary JSON schema."""
    return _schemas_data_root() / "vocabulary.schema.json"


def bundled_data_root() -> Path:
    """Bundled package data (configurations, skills manifest, setup templates)."""
    return Path(str(files("opentide.data")))


def bundled_configurations_root() -> Path:
    """Default platform and global configuration templates."""
    return bundled_data_root() / "configurations"
