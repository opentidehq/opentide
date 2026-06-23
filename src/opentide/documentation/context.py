"""Runtime context used by documentation rendering."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.types import DocumentFlavor


def resolve_flavor(*, override: str | None = None, default: str = "generic") -> DocumentFlavor:
    """Resolve markdown flavor from CLI override, CI env, or config default."""
    if override:
        return DocumentFlavor(override.replace("-", "_"))
    if os.getenv("TF_BUILD"):
        return DocumentFlavor.azure_devops
    if os.getenv("GITHUB_ACTIONS"):
        return DocumentFlavor.github
    if os.getenv("CI"):
        return DocumentFlavor.gitlab
    return DocumentFlavor(default.replace("-", "_"))


@dataclass(frozen=True)
class DocumentationContext:
    """Shared context object for render and publish phases."""

    flavor: DocumentFlavor
    output_dir: Path
    formatter: MarkdownFormatter
    folder_index_pages: bool = True
    uuid_permalinks: bool = False
