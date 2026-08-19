"""Markdown link helpers."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.types import DocumentScope

if TYPE_CHECKING:
    from opentide.documentation.catalog import DocumentationCatalog

FOLDER_BY_SCOPE = {
    DocumentScope.rules: "Rules",
    DocumentScope.objectives: "Objectives",
    DocumentScope.threats: "Threats",
}

FOLDER_BY_TYPE = {
    "rule": "Rules",
    "objective": "Objectives",
    "threat": "Threats",
}


def slugify(name: str) -> str:
    """Create a filesystem-safe slug from an object name."""
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name.strip()).strip("-").lower()
    return slug or "object"


def heading_anchor(title: str) -> str:
    """GitHub-style heading anchor for in-page jumps."""
    return slugify(title)


def wiki_target(*, folder: str, slug: str) -> str:
    """Build a markdown target for object pages.

    Prefer :func:`page_href` for pages that must resolve relative to a current folder.
    """
    return f"{folder}/{slug}.md"


def page_href(
    *,
    from_folder: str,
    to_folder: str,
    filename: str,
    anchor: str | None = None,
) -> str:
    """Build a relative href from one wiki folder to a page in another."""
    if from_folder == to_folder:
        href = filename
    elif not from_folder or from_folder == ".":
        href = f"{to_folder}/{filename}"
    else:
        href = f"../{to_folder}/{filename}"
    if anchor:
        href = f"{href}#{anchor}"
    return href


def render_link(formatter: MarkdownFormatter, text: str, target: str, *, wiki: bool = False) -> str:
    """Render a normal or wiki-formatted link."""
    if wiki:
        return formatter.wiki_link(text, target)
    return formatter.link(text, target)


def object_link(
    formatter: MarkdownFormatter,
    catalog: DocumentationCatalog,
    uuid: str,
    *,
    from_folder: str,
    uuid_permalinks: bool = False,
    wiki: bool = False,
) -> str:
    """Render a backlink to an object or to a signal heading on its parent objective."""
    signal = catalog.resolve_signal(uuid)
    if signal is not None:
        parent = catalog.resolve_record(signal.parent_uuid)
        if parent is None:
            return f"{signal.name} (`{uuid}`)"
        filename = formatter.page_filename(
            slugify(parent.name),
            parent.uuid if uuid_permalinks else None,
        )
        href = page_href(
            from_folder=from_folder,
            to_folder=FOLDER_BY_SCOPE[DocumentScope.objectives],
            filename=filename,
            anchor=heading_anchor(signal.name),
        )
        link = render_link(formatter, signal.name, href, wiki=wiki)
        return f"{link} (`{uuid}`)"

    record = catalog.resolve_record(uuid)
    if record is None:
        name = catalog.resolve_name(uuid)
        if name != uuid:
            return f"{name} (`{uuid}`)"
        return f"`{uuid}`"

    folder = FOLDER_BY_SCOPE.get(record.object_type)
    if folder is None:
        return f"`{uuid}`"

    filename = formatter.page_filename(
        slugify(record.name),
        record.uuid if uuid_permalinks else None,
    )
    href = page_href(from_folder=from_folder, to_folder=folder, filename=filename)
    link = render_link(formatter, record.name, href, wiki=wiki)
    return f"{link} (`{uuid}`)"
