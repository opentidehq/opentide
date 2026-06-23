"""Publish path resolution."""

from __future__ import annotations

from pathlib import Path

from opentide.documentation.context import DocumentationContext
from opentide.documentation.markdown.links import slugify
from opentide.documentation.types import PublishTarget


def targets(ctx: DocumentationContext) -> PublishTarget:
    """Resolve output directories for object documentation."""
    root = ctx.output_dir
    return PublishTarget(
        output_root=root,
        rules_dir=root / "Rules",
        objectives_dir=root / "Objectives",
        threats_dir=root / "Threats",
    )


def page_path(
    ctx: DocumentationContext,
    *,
    folder: Path,
    name: str,
    uuid: str,
) -> Path:
    """Resolve output path for a single object page."""
    slug = slugify(name)
    filename = ctx.formatter.page_filename(slug, uuid if ctx.uuid_permalinks else None)
    return folder / filename
