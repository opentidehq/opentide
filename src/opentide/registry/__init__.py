"""opentide workspace registry — discovery, paths, and in-memory index build."""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentide.registry.artifacts import schema_artifact_name, template_artifact_name
from opentide.registry.discovery import discover_workspace, is_opentide_workspace
from opentide.registry.paths import resolve_workspace_paths

if TYPE_CHECKING:
    from opentide.registry.builder import RegistryBuilder

__all__ = [
    "RegistryBuilder",
    "discover_workspace",
    "is_opentide_workspace",
    "resolve_workspace_paths",
    "schema_artifact_name",
    "template_artifact_name",
]


def __getattr__(name: str) -> object:
    """Resolve ``RegistryBuilder`` on first use.

    ``opentide.core.files`` imports ``opentide.registry.discovery``, and the
    builder imports ``opentide.core.files``: loading the builder here would make
    importing ``opentide.core.files`` first a circular import.
    """
    if name == "RegistryBuilder":
        from opentide.registry.builder import RegistryBuilder

        return RegistryBuilder
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
