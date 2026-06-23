"""Index page generation."""

from __future__ import annotations

from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.links import render_link, slugify, wiki_target
from opentide.documentation.publish.writer import write_page
from opentide.documentation.types import DocumentRecord, PublishTarget


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
            record.name,
            wiki_target(folder=folder, slug=slug),
            wiki=ctx.flavor.value in {"gitlab", "azure_devops"},
        )
        rows.append([link, record.uuid])
    toc = formatter.table_of_contents()
    table = formatter.index_table(["Name", "UUID"], rows)
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
        index_name = "README.md" if ctx.flavor.value in {"github", "generic"} else ".order"
        if index_name == "README.md":
            write_page(folder_path / index_name, content)
        else:
            write_page(folder_path / "README.md", content)

    root_rows: list[list[str]] = []
    for folder_name, title in (
        ("Rules", "Detection Rules"),
        ("Objectives", "Detection Objectives"),
        ("Threats", "Threat Vectors"),
    ):
        root_rows.append(
            [render_link(ctx.formatter, title, f"{folder_name}/README.md"), folder_name]
        )
    root = render_index(
        ctx.formatter,
        title="OpenTide Documentation",
        folder=".",
        records=[],
        ctx=ctx,
    )
    if root_rows:
        root = ctx.formatter.heading(1, "OpenTide Documentation") + ctx.formatter.index_table(
            ["Section", "Folder"], root_rows
        )
    write_page(catalog_targets.output_root / "README.md", root)
