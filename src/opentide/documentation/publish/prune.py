"""Remove object pages that no catalogue record writes any more."""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.markdown.links import page_slug
from opentide.documentation.publish.paths import page_path, targets
from opentide.documentation.types import DocumentScope

OBJECT_SCOPES = (DocumentScope.rules, DocumentScope.objectives, DocumentScope.threats)

# Every object page opens with a Metadata table whose first row is the object's
# UUID. A file in an object folder without that row is not one ``generate docs``
# wrote, so it is never removed.
_UUID_ROW = re.compile(r"^\| UUID \| `[^`\n]+` \|$", re.MULTILINE)


def is_generated_page(path: Path) -> bool:
    """True when *path* reads like an object page this generator wrote."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return "## Metadata\n" in text and _UUID_ROW.search(text) is not None


def prune_stale_pages(
    ctx: DocumentationContext,
    catalog: DocumentationCatalog,
    scopes: Iterable[DocumentScope] = OBJECT_SCOPES,
) -> list[Path]:
    """Delete generated pages in the *scopes* folders that no record maps to.

    A renamed or deleted object leaves its old page behind, and a full run never
    removed it. Only ``*.md`` files directly in the object folders that carry the
    generator's Metadata table are candidates; ``README.md`` and anything else a
    user put there stay.
    """
    pub = targets(ctx)
    folders = {
        DocumentScope.rules: (pub.rules_dir, catalog.rules),
        DocumentScope.objectives: (pub.objectives_dir, catalog.objectives),
        DocumentScope.threats: (pub.threats_dir, catalog.threats),
    }
    removed: list[Path] = []
    for scope in scopes:
        folder, records = folders[scope]
        if not folder.is_dir():
            continue
        live = [
            page_path(
                ctx, folder=folder, name=record.name, uuid=record.uuid, slug=page_slug(record)
            )
            for record in records
        ]
        live_names = {path.name for path in live}
        # On a case-insensitive filesystem a live page can sit under an older
        # spelling of its name, so compare files, not only names.
        live_files = {_file_id(path) for path in live} - {None}
        for path in sorted(folder.glob("*.md")):
            if path.name in live_names or path.name == "README.md":
                continue
            if _file_id(path) in live_files or not is_generated_page(path):
                continue
            path.unlink()
            removed.append(path)
    return removed


def _file_id(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_dev, stat.st_ino
