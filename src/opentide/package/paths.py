"""Package-internal bundled asset paths (not client workspace paths)."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def _schemas_data_root() -> Path:
    return Path(str(files("opentide.schemas"))) / "data"


def platform_templates_root() -> Path:
    """Bundled platform block templates, one ``<platform>.template.yaml`` per platform.

    Rendered from the platform models and kept in step with them by
    ``tests/test_generation/test_template_goldens.py``; ``opentide generate
    templates`` never writes here (the package may be read-only).
    """
    return _schemas_data_root() / "platform_templates"


def platform_template_name(platform: str) -> str:
    """File name of *platform*'s block template: ``<platform>.template.yaml``."""
    return f"{platform}.template.yaml"


def vocabulary_schema_path() -> Path:
    """Bundled vocabulary JSON schema."""
    return _schemas_data_root() / "vocabulary.schema.json"


def bundled_data_root() -> Path:
    """Bundled package data (configurations, skills manifest, setup templates)."""
    return Path(str(files("opentide.data")))


def bundled_configurations_root() -> Path:
    """Default configuration files: paths, deployment, platforms, ..."""
    return bundled_data_root() / "configurations"
