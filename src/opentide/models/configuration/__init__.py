"""Pydantic models of the configuration TOML files under `.opentide/configurations/`.

One model per file. The CLI validates the merged document (bundled, then the
workspace, then the parent instance) against it, and the exported JSON Schema
of each file is `model_json_schema()` of the same model.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from pydantic import BaseModel

from opentide.models.configuration.base import ConfigurationModel
from opentide.models.configuration.deployment import (
    DebugSettings,
    DeploymentConfiguration,
    DeploymentResponder,
    DeploymentStatusEntry,
    PromotionSettings,
)
from opentide.models.configuration.documentation import DocumentationConfiguration
from opentide.models.configuration.paths import PathsConfiguration
from opentide.models.configuration.platforms import (
    PLATFORM_CONFIGURATION_MODELS,
    PlatformConfiguration,
    PlatformConfigurationBase,
)
from opentide.models.configuration.schema import SchemaConfiguration
from opentide.models.configuration.sharing import MispIntegration, SharingConfiguration
from opentide.models.visibility import VisibilityConfig

#: Model of each top-level configuration file, keyed by file name.
CONFIGURATION_FILE_MODELS: dict[str, type[BaseModel]] = {
    "paths.toml": PathsConfiguration,
    "global.toml": PathsConfiguration,
    "deployment.toml": DeploymentConfiguration,
    "schema.toml": SchemaConfiguration,
    "visibility.toml": VisibilityConfig,
    "documentation.toml": DocumentationConfiguration,
    "sharing.toml": SharingConfiguration,
}

#: Router key of a platform file opentide has no dedicated model for.
GENERIC_PLATFORM_FILE = "platforms/*.toml"


def configuration_files() -> dict[str, type[BaseModel]]:
    """Every routed configuration file name and its model, platform files included."""
    files = dict(CONFIGURATION_FILE_MODELS)
    for identifier, model in PLATFORM_CONFIGURATION_MODELS.items():
        files[f"platforms/{identifier}.toml"] = model
    files[GENERIC_PLATFORM_FILE] = PlatformConfiguration
    return files


def configuration_file_key(path: str | PurePosixPath) -> str | None:
    """Router key of a configuration file path, or `None` when it is not one.

    *path* may be absolute or relative to `.opentide/configurations/`; only the
    file name, and the `platforms` folder for a platform file, are read.
    """
    parts = PurePosixPath(str(path).replace("\\", "/")).parts
    if not parts or not parts[-1].endswith(".toml"):
        return None
    for position, part in enumerate(parts[:-1]):
        # `.opentide/schemas/` holds generated artifacts, never configuration.
        if part == ".opentide" and parts[position + 1] == "schemas":
            return None
    if len(parts) >= 2 and parts[-2] == "sharing":
        # `configurations/sharing/` is not a configuration location.
        return None
    name = parts[-1]
    if len(parts) >= 2 and parts[-2] in {"platforms", "systems"}:
        identifier = name.removesuffix(".toml")
        if identifier in PLATFORM_CONFIGURATION_MODELS:
            return f"platforms/{identifier}.toml"
        return GENERIC_PLATFORM_FILE
    if name in CONFIGURATION_FILE_MODELS:
        return name
    return None


def configuration_model_for(path: str | PurePosixPath) -> type[BaseModel] | None:
    """Model of a configuration file path, or `None` when it is not one."""
    key = configuration_file_key(path)
    return configuration_files()[key] if key is not None else None


__all__ = [
    "CONFIGURATION_FILE_MODELS",
    "GENERIC_PLATFORM_FILE",
    "PLATFORM_CONFIGURATION_MODELS",
    "ConfigurationModel",
    "DebugSettings",
    "DeploymentConfiguration",
    "DeploymentResponder",
    "DeploymentStatusEntry",
    "DocumentationConfiguration",
    "MispIntegration",
    "PathsConfiguration",
    "PlatformConfiguration",
    "PlatformConfigurationBase",
    "PromotionSettings",
    "SchemaConfiguration",
    "SharingConfiguration",
    "VisibilityConfig",
    "configuration_file_key",
    "configuration_files",
    "configuration_model_for",
]
