"""Documentation configuration loading."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from opentide.core.registry import OpenTide
from opentide.documentation.context import resolve_flavor
from opentide.documentation.types import DocumentFlavor


@dataclass(frozen=True)
class DocumentationSettings:
    """Typed settings consumed by the documentation subsystem."""

    output_dir: Path
    flavor: DocumentFlavor
    folder_index_pages: bool
    uuid_permalinks: bool
    relations_direction: Literal["upstream", "downstream", "both"]
    index_relation_counts: bool
    index_icons: bool


def load_settings(*, output: str | None = None, flavor: str | None = None) -> DocumentationSettings:
    """Load documentation settings from config with CLI overrides."""
    docs_cfg = OpenTide.Configurations.Documentation.Index
    global_cfg = OpenTide.Configurations.Global.Index
    core_paths = global_cfg.get("paths", {}).get("core", {})

    configured_output = docs_cfg.get("output") or core_paths.get("docs_folder") or "docs"
    target_dir = Path(output or configured_output)
    if not target_dir.is_absolute():
        from opentide.core.root import get_repo_root

        target_dir = get_repo_root() / target_dir
    flavor_cfg = docs_cfg.get("flavor", {})
    default_flavor = (
        str(flavor_cfg.get("default", "generic"))
        if isinstance(flavor_cfg, dict)
        else str(flavor_cfg or "generic")
    )
    resolved = resolve_flavor(override=flavor, default=default_flavor)
    folder_index_pages = bool(docs_cfg.get("folder_index_pages", True))
    gitlab_cfg = docs_cfg.get("gitlab", {})
    uuid_permalinks = bool(gitlab_cfg.get("uuid_permalinks", False))
    diagrams_cfg = docs_cfg.get("diagrams", {})
    configured_direction = str(diagrams_cfg.get("relations_direction", "both"))
    if configured_direction not in {"upstream", "downstream", "both"}:
        configured_direction = "both"
    index_cfg = docs_cfg.get("index", {})
    index_relation_counts = bool(index_cfg.get("relation_counts", True))
    index_icons = bool(index_cfg.get("icons", False))
    return DocumentationSettings(
        output_dir=target_dir,
        flavor=resolved,
        folder_index_pages=folder_index_pages,
        uuid_permalinks=uuid_permalinks,
        relations_direction=cast(Literal["upstream", "downstream", "both"], configured_direction),
        index_relation_counts=index_relation_counts,
        index_icons=index_icons,
    )
