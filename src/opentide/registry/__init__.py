"""OpenTide workspace registry — discovery, paths, and in-memory index build."""

from opentide.registry.artifacts import schema_artifact_name, template_artifact_name
from opentide.registry.builder import RegistryBuilder
from opentide.registry.discovery import discover_workspace, is_opentide_workspace
from opentide.registry.paths import resolve_workspace_paths

__all__ = [
    "RegistryBuilder",
    "discover_workspace",
    "is_opentide_workspace",
    "resolve_workspace_paths",
    "schema_artifact_name",
    "template_artifact_name",
]
