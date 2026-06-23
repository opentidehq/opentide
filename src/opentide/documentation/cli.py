"""CLI entrypoint for documentation generation."""

from __future__ import annotations

import structlog

from opentide.documentation.catalog import build_catalog
from opentide.documentation.config import load_settings
from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.objects.objective import render_objective_page
from opentide.documentation.objects.rule import render_rule_page
from opentide.documentation.objects.threat import render_threat_page
from opentide.documentation.publish.index import write_index
from opentide.documentation.publish.paths import page_path, targets
from opentide.documentation.publish.writer import write_page
from opentide.documentation.types import DocumentScope

logger = structlog.get_logger("opentide.documentation.cli")


def _build_context(*, output: str | None = None, flavor: str | None = None) -> DocumentationContext:
    settings = load_settings(output=output, flavor=flavor)
    return DocumentationContext(
        flavor=settings.flavor,
        output_dir=settings.output_dir,
        formatter=formatter_for(settings.flavor),
        folder_index_pages=settings.folder_index_pages,
        uuid_permalinks=settings.uuid_permalinks,
    )


def run_index(ctx: DocumentationContext) -> None:
    """Write folder and root index pages."""
    catalog = build_catalog()
    pub = targets(ctx)
    write_index(
        ctx,
        pub,
        rules=catalog.rules,
        objectives=catalog.objectives,
        threats=catalog.threats,
    )
    logger.info("index_written", output=str(ctx.output_dir))


def run_objects(ctx: DocumentationContext, scope: DocumentScope | None = None) -> dict[str, int]:
    """Write object pages for one or all scopes."""
    catalog = build_catalog()
    pub = targets(ctx)
    counts: dict[str, int] = {"rules": 0, "objectives": 0, "threats": 0}

    if scope in (None, DocumentScope.threats):
        for record in catalog.threats:
            write_page(
                page_path(ctx, folder=pub.threats_dir, name=record.name, uuid=record.uuid),
                render_threat_page(record.model, ctx, catalog),
            )
            counts["threats"] += 1

    if scope in (None, DocumentScope.objectives):
        for record in catalog.objectives:
            write_page(
                page_path(ctx, folder=pub.objectives_dir, name=record.name, uuid=record.uuid),
                render_objective_page(record.model, ctx, catalog),
            )
            counts["objectives"] += 1

    if scope in (None, DocumentScope.rules):
        for record in catalog.rules:
            write_page(
                page_path(ctx, folder=pub.rules_dir, name=record.name, uuid=record.uuid),
                render_rule_page(record.model, ctx, catalog),
            )
            counts["rules"] += 1

    return counts


def run(
    *,
    scope: str | None = None,
    output: str | None = None,
    flavor: str | None = None,
) -> dict[str, object]:
    """Run documentation generation for a scope or full pipeline."""
    ctx = _build_context(output=output, flavor=flavor)
    resolved = DocumentScope(scope) if scope else None

    if resolved is DocumentScope.index:
        run_index(ctx)
        return {"message": "Index pages written", "output": str(ctx.output_dir)}

    counts = run_objects(ctx, resolved)
    if resolved is None:
        run_index(ctx)
        return {
            "message": "Full documentation pipeline completed",
            "counts": counts,
            "output": str(ctx.output_dir),
        }

    return {"message": f"Documentation scope {resolved.value} completed", "counts": counts}
