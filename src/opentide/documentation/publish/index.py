"""Index page generation."""

from __future__ import annotations

from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.links import (
    FOLDER_BY_SCOPE,
    page_href,
    render_link,
    slugify,
)
from opentide.documentation.publish.writer import write_page
from opentide.documentation.types import DocumentRecord, DocumentScope, PublishTarget
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


def _as_cell(value: object) -> str:
    return value if isinstance(value, str) else ""


def _extra_headers(scope: DocumentScope | None) -> list[str]:
    if scope == DocumentScope.rules:
        return ["Status", "Severity"]
    if scope == DocumentScope.objectives:
        return ["Priority"]
    if scope == DocumentScope.threats:
        return ["Criticality"]
    return []


def _extra_cells(record: DocumentRecord) -> list[str]:
    model = record.model
    if record.object_type == DocumentScope.rules:
        status = _as_cell(getattr(model, "status", None))
        severity = _as_cell(getattr(model, "severity", None))
        return [status, severity]
    if record.object_type == DocumentScope.objectives:
        body = getattr(model, "objective", None)
        return [_as_cell(getattr(body, "priority", None))]
    if record.object_type == DocumentScope.threats:
        return [_as_cell(getattr(model, "criticality", None))]
    return []


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
    scope = records[0].object_type if records else None
    extra_headers = _extra_headers(scope)
    from_folder = ""
    if scope is not None:
        from_folder = FOLDER_BY_SCOPE.get(scope, folder)
    elif folder not in {"", "."}:
        from_folder = folder
    rows: list[list[str]] = []
    for record in records:
        to_folder = FOLDER_BY_SCOPE.get(record.object_type, folder)
        slug = record.uuid if ctx.uuid_permalinks else slugify(record.name)
        filename = formatter.page_filename(slug, record.uuid if ctx.uuid_permalinks else None)
        href = page_href(from_folder=from_folder, to_folder=to_folder, filename=filename)
        link = render_link(
            formatter,
            _render_name(record, ctx),
            href,
            wiki=ctx.flavor.value in {"gitlab", "azure_devops"},
        )
        row = [link, record.uuid, *_extra_cells(record)]
        if ctx.index_relation_counts:
            row.append(str(_relation_count(record, ctx)))
        rows.append(row)
    toc = formatter.table_of_contents()
    headers = ["Name", "UUID", *extra_headers]
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
        row = [
            render_link(ctx.formatter, section_title, f"{folder_name}/README.md"),
            folder_name,
        ]
        if ctx.index_relation_counts:
            count = len({"Rules": rules, "Objectives": objectives, "Threats": threats}[folder_name])
            row.append(str(count))
        root_rows.append(row)
    if root_rows:
        headers = ["Section", "Folder"]
        if ctx.index_relation_counts:
            headers.append("Objects")
        root = ctx.formatter.heading(1, "OpenTide Documentation") + ctx.formatter.index_table(
            headers, root_rows
        )
        write_page(catalog_targets.output_root / "README.md", root)
