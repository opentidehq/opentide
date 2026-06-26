"""Programmatic documentation API."""

from __future__ import annotations

from opentide.documentation.catalog import DocumentationCatalog, build_catalog
from opentide.documentation.config import load_settings
from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.objects.objective import render_objective_page
from opentide.documentation.objects.rule import render_rule_page
from opentide.documentation.objects.threat import render_threat_page
from opentide.documentation.publish.index import write_index
from opentide.documentation.publish.paths import page_path, targets
from opentide.documentation.publish.writer import write_page
from opentide.documentation.types import DocumentFlavor
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector


def _context(*, output: str | None = None, flavor: str | None = None) -> DocumentationContext:
    settings = load_settings(output=output, flavor=flavor)
    return DocumentationContext(
        flavor=settings.flavor,
        output_dir=settings.output_dir,
        formatter=formatter_for(settings.flavor),
        folder_index_pages=settings.folder_index_pages,
        uuid_permalinks=settings.uuid_permalinks,
        relations_direction=settings.relations_direction,
        index_relation_counts=settings.index_relation_counts,
        index_icons=settings.index_icons,
    )


def render_rule(
    rule: DetectionRule,
    *,
    flavor: DocumentFlavor | None = None,
    catalog: DocumentationCatalog | None = None,
) -> str:
    """Render a single rule to markdown."""
    ctx = _context(flavor=flavor.value if flavor else None)
    cat = catalog or build_catalog()
    return render_rule_page(rule, ctx, cat)


def render_objective(
    objective: DetectionObjective,
    *,
    flavor: DocumentFlavor | None = None,
    catalog: DocumentationCatalog | None = None,
) -> str:
    """Render a single objective to markdown."""
    ctx = _context(flavor=flavor.value if flavor else None)
    cat = catalog or build_catalog()
    return render_objective_page(objective, ctx, cat)


def render_threat(
    threat: ThreatVector,
    *,
    flavor: DocumentFlavor | None = None,
    catalog: DocumentationCatalog | None = None,
) -> str:
    """Render a single threat to markdown."""
    ctx = _context(flavor=flavor.value if flavor else None)
    cat = catalog or build_catalog()
    return render_threat_page(threat, ctx, cat)


def write_rules(
    ctx: DocumentationContext | None = None,
    catalog: DocumentationCatalog | None = None,
) -> int:
    """Write all rule pages."""
    context = ctx or _context()
    cat = catalog or build_catalog()
    pub = targets(context)
    count = 0
    for record in cat.rules:
        content = render_rule_page(record.model, context, cat)
        path = page_path(context, folder=pub.rules_dir, name=record.name, uuid=record.uuid)
        write_page(path, content)
        count += 1
    return count


def write_objectives(
    ctx: DocumentationContext | None = None, catalog: DocumentationCatalog | None = None
) -> int:
    """Write all objective pages."""
    context = ctx or _context()
    cat = catalog or build_catalog()
    pub = targets(context)
    count = 0
    for record in cat.objectives:
        content = render_objective_page(record.model, context, cat)
        path = page_path(context, folder=pub.objectives_dir, name=record.name, uuid=record.uuid)
        write_page(path, content)
        count += 1
    return count


def write_threats(
    ctx: DocumentationContext | None = None,
    catalog: DocumentationCatalog | None = None,
) -> int:
    """Write all threat pages."""
    context = ctx or _context()
    cat = catalog or build_catalog()
    pub = targets(context)
    count = 0
    for record in cat.threats:
        content = render_threat_page(record.model, context, cat)
        path = page_path(context, folder=pub.threats_dir, name=record.name, uuid=record.uuid)
        write_page(path, content)
        count += 1
    return count


def write_all(
    *,
    include_index: bool = True,
    output: str | None = None,
    flavor: str | None = None,
) -> dict[str, int]:
    """Write all object pages and optionally index pages."""
    ctx = _context(output=output, flavor=flavor)
    cat = build_catalog()
    pub = targets(ctx)
    counts = {
        "rules": write_rules(ctx, cat),
        "objectives": write_objectives(ctx, cat),
        "threats": write_threats(ctx, cat),
    }
    if include_index:
        write_index(ctx, pub, rules=cat.rules, objectives=cat.objectives, threats=cat.threats)
    return counts
