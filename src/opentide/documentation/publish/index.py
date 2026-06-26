"""Index page generation."""

from __future__ import annotations

from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.links import render_link, slugify, wiki_target
from opentide.documentation.publish.writer import write_page
from opentide.documentation.types import DocumentRecord, PublishTarget
from opentide.generation import framework as fw

_INDEX_ICON_BY_SCOPE = {
    "rules": ":shield:",
    "objectives": ":dart:",
    "threats": ":warning:",
}


def _render_name(record: DocumentRecord, ctx: DocumentationContext) -> str:
    if not ctx.index_icons:
        return record.name
    icon = _INDEX_ICON_BY_SCOPE.get(record.object_type.value, "")
    return f"{icon} {record.name}".strip()


def _relation_count(record: DocumentRecord, ctx: DocumentationContext) -> int:
    relations = fw.relations_list(record.uuid, mode="flat", direction=ctx.relations_direction)
    unique: set[str] = set()
    for ids in relations.values():
        unique.update(ids)
    return len(unique)


def _folder_order_entries(ctx: DocumentationContext, records: list[DocumentRecord]) -> list[str]:
    entries = ["README"]
    for record in records:
        slug = record.uuid if ctx.uuid_permalinks else slugify(record.name)
        filename = ctx.formatter.page_filename(slug, record.uuid)
        entries.append(filename.removesuffix(".md"))
    return entries


def render_index(
    formatter: MarkdownFormatter,
    *,
    title: str,
    folder: str,
    records: list[DocumentRecord],
    ctx: DocumentationContext,
) -> str:
    """Render a folder index page."""
    rows: list[list[str]] = []
    for record in records:
        slug = record.uuid if ctx.uuid_permalinks else slugify(record.name)
        link = render_link(
            formatter,
            _render_name(record, ctx),
            wiki_target(folder=folder, slug=slug),
            wiki=ctx.flavor.value in {"gitlab", "azure_devops"},
        )
        row = [link, record.uuid]
        if ctx.index_relation_counts:
            row.append(str(_relation_count(record, ctx)))
        rows.append(row)
    toc = formatter.table_of_contents()
    headers = ["Name", "UUID"]
    if ctx.index_relation_counts:
        headers.append("Related")
    table = formatter.index_table(headers, rows)
    parts = [formatter.heading(1, title)]
    if toc:
        parts.append(toc)
    parts.append(table)
    return "".join(parts)


def write_index(
    ctx: DocumentationContext,
    catalog_targets: PublishTarget,
    *,
    rules: list[DocumentRecord],
    objectives: list[DocumentRecord],
    threats: list[DocumentRecord],
) -> None:
    """Write folder index pages and optional root README."""
    if not ctx.folder_index_pages:
        return

    folders = (
        (catalog_targets.rules_dir, "Rules", "Detection Rules", rules),
        (catalog_targets.objectives_dir, "Objectives", "Detection Objectives", objectives),
        (catalog_targets.threats_dir, "Threats", "Threat Vectors", threats),
    )
    for folder_path, folder_name, title, records in folders:
        if not records:
            continue
        content = render_index(
            ctx.formatter,
            title=title,
            folder=folder_name,
            records=records,
            ctx=ctx,
        )
        write_page(folder_path / "README.md", content)
        if ctx.flavor.value == "gitlab":
            order_entries = _folder_order_entries(ctx, records)
            write_page(folder_path / ".order", "\n".join(order_entries) + "\n")

    root_rows: list[list[str]] = []
    for folder_name, title in (
        ("Rules", "Detection Rules"),
        ("Objectives", "Detection Objectives"),
        ("Threats", "Threat Vectors"),
    ):
        section_title = title
        if ctx.index_icons:
            icon = _INDEX_ICON_BY_SCOPE.get(folder_name.lower(), "")
            if icon:
                section_title = f"{icon} {title}"
        row = [render_link(ctx.formatter, section_title, f"{folder_name}/README.md"), folder_name]
        if ctx.index_relation_counts:
            count = len({"Rules": rules, "Objectives": objectives, "Threats": threats}[folder_name])
            row.append(str(count))
        root_rows.append(row)
    root = render_index(
        ctx.formatter,
        title="OpenTide Documentation",
        folder=".",
        records=[],
        ctx=ctx,
    )
    if root_rows:
        headers = ["Section", "Folder"]
        if ctx.index_relation_counts:
            headers.append("Objects")
        root = ctx.formatter.heading(1, "OpenTide Documentation") + ctx.formatter.index_table(
            headers, root_rows
        )
    write_page(catalog_targets.output_root / "README.md", root)
