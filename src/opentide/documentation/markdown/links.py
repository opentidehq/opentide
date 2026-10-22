"""Markdown link helpers."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import TYPE_CHECKING

from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.types import DocumentRecord, DocumentScope

if TYPE_CHECKING:
    from opentide.documentation.catalog import DocumentationCatalog

FOLDER_BY_SCOPE = {
    DocumentScope.rules: "rules",
    DocumentScope.objectives: "objectives",
    DocumentScope.threats: "threats",
}

FOLDER_BY_TYPE = {
    "rule": "rules",
    "objective": "objectives",
    "threat": "threats",
}


def slugify(name: str) -> str:
    """Create a filesystem-safe slug from an object name."""
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name.strip()).strip("-").lower()
    return slug or "object"


def page_slug(record: DocumentRecord) -> str:
    """Filename stem of *record*'s page, before the flavor adds its suffix."""
    return record.slug or slugify(record.name)


def unique_slugs(records: list[DocumentRecord]) -> list[DocumentRecord]:
    """Give each record in one folder a page slug no other record shares.

    Two names can slugify alike (``Sentinel KQL Rule`` and ``Sentinel-KQL rule``),
    and their pages overwrote each other. The record with the lowest UUID keeps
    the plain slug, so a page is renamed only when its name collides; the others
    get a UUID suffix, the same one ``opentide lint`` uses for colliding files.
    """
    groups: dict[str, list[int]] = {}
    for position, record in enumerate(records):
        groups.setdefault(slugify(record.name), []).append(position)
    taken = set(groups)
    slugs = [""] * len(records)
    for slug, positions in groups.items():
        first, *others = sorted(positions, key=lambda position: records[position].uuid)
        slugs[first] = slug
        for position in others:
            suffix = (records[position].uuid or "object")[:8]
            candidate = f"{slug}-{suffix}"
            index = 1
            while candidate in taken:
                candidate = f"{slug}-{suffix}-{index}"
                index += 1
            taken.add(candidate)
            slugs[position] = candidate
    return [replace(record, slug=slug) for record, slug in zip(records, slugs, strict=True)]


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
            page_slug(parent),
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
        page_slug(record),
        record.uuid if uuid_permalinks else None,
    )
    href = page_href(from_folder=from_folder, to_folder=folder, filename=filename)
    link = render_link(formatter, record.name, href, wiki=wiki)
    return f"{link} (`{uuid}`)"
