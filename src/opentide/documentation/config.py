"""Documentation configuration loading."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from opentide.core.registry import Opentide
from opentide.documentation.context import resolve_flavor
from opentide.documentation.types import DocumentFlavor
from opentide.models.configuration.documentation import DocumentationConfiguration
from opentide.models.configuration.loading import validate_configuration


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
    docs = validate_configuration(
        DocumentationConfiguration,
        Opentide.Configurations.Documentation.Index,
        file_key="documentation.toml",
    )
    global_cfg = Opentide.Configurations.Global.Index
    core_paths = global_cfg.get("paths", {}).get("core", {})

    configured_output = docs.output or core_paths.get("docs_folder") or "docs"
    target_dir = Path(output or configured_output)
    if not target_dir.is_absolute():
        from opentide.core.root import get_repo_root

        target_dir = get_repo_root() / target_dir
    resolved = resolve_flavor(override=flavor, default=docs.default_flavor().value)
    # uuid permalinks are a GitLab wiki setting; do not apply them to GitHub/generic.
    uuid_permalinks = resolved is DocumentFlavor.gitlab and docs.gitlab.uuid_permalinks
    return DocumentationSettings(
        output_dir=target_dir,
        flavor=resolved,
        folder_index_pages=docs.folder_index_pages,
        uuid_permalinks=uuid_permalinks,
        relations_direction=docs.diagrams.relations_direction,
        index_relation_counts=docs.index.relation_counts,
        index_icons=docs.index.icons,
    )
