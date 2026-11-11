"""Index pages: one per object folder, and the catalogue overview at the root.

A folder index is a sortable table of its objects with the facts a reader
scans for: a rule's severity and where it deploys at which status, an
objective's signals and rules, a threat's kill chain and detection coverage.
The root page summarises the catalogue: how many objects of each family,
how many rules sit at each status on each platform, and how much of the
threat landscape is covered.
"""

from __future__ import annotations

from collections.abc import Sequence

from opentide.documentation.context import DocumentationContext
from opentide.documentation.facts.platforms import platform_label
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.links import (
    FOLDER_BY_SCOPE,
    page_href,
    page_slug,
    render_link,
)
from opentide.documentation.markdown.page import Page, join, section
from opentide.documentation.markdown.text import inline_code, join_lines, plural, table_cell
from opentide.documentation.publish.writer import write_page
from opentide.documentation.types import DocumentRecord, DocumentScope, PublishTarget
from opentide.documentation.vocabulary import enrich
from opentide.generation import framework as fw
from opentide.generation.errors import rendering
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector

_INDEX_ICON_BY_SCOPE = {
    "rules": ":shield:",
    "objectives": ":dart:",
    "threats": ":warning:",
}

_SCOPE_BY_FOLDER = {
    "rules": DocumentScope.rules,
    "objectives": DocumentScope.objectives,
    "threats": DocumentScope.threats,
}

_FOLDERS = (
    ("rules", "Detection Rules"),
    ("objectives", "Detection Objectives"),
    ("threats", "Threat Vectors"),
)

_NOUNS = {
    DocumentScope.rules: "rule",
    DocumentScope.objectives: "objective",
    DocumentScope.threats: "threat vector",
}

_INTRODUCTIONS = {
    DocumentScope.rules: (
        "Detection rules: the queries opentide deploys, with the status each platform block "
        "carries."
    ),
    DocumentScope.objectives: (
        "Detection objectives: what to detect about a threat, broken into signals that rules "
        "implement."
    ),
    DocumentScope.threats: (
        "Threat vectors: adversary behaviours, assessed and chained, with the detection "
        "coverage they have."
    ),
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
    return table_cell(value) if isinstance(value, str) and value else "-"


def _extra_headers(scope: DocumentScope | None) -> list[str]:
    if scope == DocumentScope.rules:
        return ["Severity", "Platforms and status", "ATT&CK"]
    if scope == DocumentScope.objectives:
        return ["Priority", "Signals", "Threats"]
    if scope == DocumentScope.threats:
        return ["Criticality", "Kill chain", "ATT&CK"]
    return []


def _extra_cells(record: DocumentRecord) -> list[str]:
    model = record.model
    if record.object_type == DocumentScope.rules:
        # What deploy reads, never a model default (see ``DetectionRule.platform_statuses``).
        statuses = getattr(model, "platform_statuses", None)
        platforms = (
            join_lines(
                f"{platform_label(platform)} {inline_code(status)}"
                for platform, status in statuses.items()
            )
            if isinstance(statuses, dict)
            else ""
        )
        techniques = getattr(model, "techniques", None)
        return [
            _as_cell(getattr(model, "displayed_severity", None)),
            platforms or "-",
            _codes(techniques),
        ]
    if record.object_type == DocumentScope.objectives:
        if not isinstance(model, DetectionObjective):
            return ["-", "-", "-"]
        body = model.objective
        return [
            _as_cell(body.priority),
            str(len(body.signals)),
            str(len(body.threats or [])),
        ]
    if record.object_type == DocumentScope.threats:
        if not isinstance(model, ThreatVector):
            return [_as_cell(getattr(model, "criticality", None)), "-", "-"]
        killchain = model.threat.killchain
        phases = [killchain] if isinstance(killchain, str) else list(killchain or [])
        return [
            enrich("criticality", model.criticality).label,
            ", ".join(phases) or "-",
            _codes(model.threat.mitre_attack),
        ]
    return []


def _codes(values: object) -> str:
    if not isinstance(values, list) or not values:
        return "-"
    return ", ".join(inline_code(value) for value in values if isinstance(value, str)) or "-"


def _page_filename(ctx: DocumentationContext, record: DocumentRecord) -> str:
    """Match ``page_path``: the record's page slug; pass UUID only for GitLab permalinks."""
    return ctx.formatter.page_filename(
        page_slug(record),
        record.uuid if ctx.uuid_permalinks else None,
    )


def _folder_order_entries(ctx: DocumentationContext, records: list[DocumentRecord]) -> list[str]:
    entries = ["README"]
    for record in records:
        filename = _page_filename(ctx, record)
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
    scope = records[0].object_type if records else _SCOPE_BY_FOLDER.get(folder)
    from_folder = ""
    if scope is not None:
        from_folder = FOLDER_BY_SCOPE.get(scope, folder)
    elif folder not in {"", "."}:
        from_folder = folder
    rows: list[list[str]] = []
    for record in records:
        to_folder = FOLDER_BY_SCOPE.get(record.object_type, folder)
        filename = _page_filename(ctx, record)
        href = page_href(from_folder=from_folder, to_folder=to_folder, filename=filename)
        link = render_link(
            formatter,
            _render_name(record, ctx),
            href,
            wiki=ctx.flavor.value in {"gitlab", "azure_devops"},
        )
        row = [link, *_extra_cells(record), inline_code(record.uuid)]
        if ctx.index_relation_counts:
            with rendering(record.uuid):
                row.append(str(_relation_count(record, ctx)))
        rows.append(row)
    headers = ["Name", *_extra_headers(scope), "UUID"]
    if ctx.index_relation_counts:
        headers.append("Related")
    parts = [formatter.heading(1, title)]
    if scope in _INTRODUCTIONS:
        count = plural(len(records), _NOUNS[scope])
        parts.append(formatter.paragraph(f"{_INTRODUCTIONS[scope]} {count}."))
    parts.append(formatter.index_table(headers, rows))
    return join(parts) + "\n"


def write_index(
    ctx: DocumentationContext,
    catalog_targets: PublishTarget,
    *,
    rules: list[DocumentRecord],
    objectives: list[DocumentRecord],
    threats: list[DocumentRecord],
) -> None:
    """Write folder index pages and the root catalogue overview."""
    if not ctx.folder_index_pages:
        return

    by_folder = {"rules": rules, "objectives": objectives, "threats": threats}
    folder_paths = {
        "rules": catalog_targets.rules_dir,
        "objectives": catalog_targets.objectives_dir,
        "threats": catalog_targets.threats_dir,
    }
    for folder_name, title in _FOLDERS:
        records = by_folder[folder_name]
        content = render_index(
            ctx.formatter,
            title=title,
            folder=folder_name,
            records=records,
            ctx=ctx,
        )
        write_page(folder_paths[folder_name] / "README.md", content)
        if ctx.flavor.value == "gitlab":
            order_entries = _folder_order_entries(ctx, records)
            write_page(folder_paths[folder_name] / ".order", "\n".join(order_entries) + "\n")

    write_page(
        catalog_targets.output_root / "README.md",
        render_root_index(ctx, rules=rules, objectives=objectives, threats=threats),
    )


def render_root_index(
    ctx: DocumentationContext,
    *,
    rules: Sequence[DocumentRecord],
    objectives: Sequence[DocumentRecord],
    threats: Sequence[DocumentRecord],
) -> str:
    """The catalogue overview: sections, deployment status matrix and coverage."""
    formatter = ctx.formatter
    by_folder = {"rules": rules, "objectives": objectives, "threats": threats}
    section_rows: list[list[str]] = []
    for folder_name, title in _FOLDERS:
        label = title
        if ctx.index_icons:
            label = f"{_INDEX_ICON_BY_SCOPE[folder_name]} {title}"
        row = [render_link(formatter, label, f"{folder_name}/README.md"), folder_name]
        if ctx.index_relation_counts:
            row.append(str(len(by_folder[folder_name])))
        section_rows.append(row)
    headers = ["Section", "Folder"]
    if ctx.index_relation_counts:
        headers.append("Objects")

    page = Page(formatter, "opentide Documentation")
    page.add_lead(
        formatter.paragraph(
            f"Detection catalogue of {plural(len(threats), 'threat vector')}, "
            f"{plural(len(objectives), 'detection objective')} and "
            f"{plural(len(rules), 'detection rule')}, generated by opentide."
        ),
        formatter.index_table(headers, section_rows),
    )
    page.add(section("Deployment status", _status_matrix(ctx, rules)))
    page.add(section("Coverage", _coverage_summary(formatter, rules, objectives, threats)))
    return page.render()


def _status_matrix(ctx: DocumentationContext, records: Sequence[DocumentRecord]) -> str:
    """Rules per platform and status: what each platform runs and at which maturity."""
    counts: dict[str, dict[str, int]] = {}
    for record in records:
        statuses = getattr(record.model, "platform_statuses", None)
        if not isinstance(statuses, dict):
            continue
        for platform, status in statuses.items():
            per_platform = counts.setdefault(platform, {})
            per_platform[status] = per_platform.get(status, 0) + 1
    if not counts:
        return ""
    configured = [status.name for status in ctx.environment.statuses()]
    seen = {status for per_platform in counts.values() for status in per_platform}
    columns = [name for name in configured if name in seen]
    columns += sorted(seen - set(columns))
    rows = [
        [
            platform_label(platform),
            *[str(counts[platform].get(status, 0) or "-") for status in columns],
            str(sum(counts[platform].values())),
        ]
        for platform in sorted(counts, key=platform_label)
    ]
    headers = ["Platform", *[inline_code(status) for status in columns], "Total"]
    return ctx.formatter.table(headers, rows)


def _coverage_summary(
    formatter: MarkdownFormatter,
    rules: Sequence[DocumentRecord],
    objectives: Sequence[DocumentRecord],
    threats: Sequence[DocumentRecord],
) -> str:
    """How much of the catalogue is detected, from the objects' own links."""
    rule_models = [record.model for record in rules if isinstance(record.model, DetectionRule)]
    objective_models = [
        record.model for record in objectives if isinstance(record.model, DetectionObjective)
    ]
    if not rule_models and not objective_models and not threats:
        return ""
    implemented = {rule.detection_model for rule in rule_models if rule.detection_model}
    addressed = {uuid for model in objective_models for uuid in model.objective.threats or []}
    signals = [signal for model in objective_models for signal in model.objective.signals]
    objective_done = [
        model
        for model in objective_models
        if model.metadata.uuid in implemented
        or any(signal.uuid in implemented for signal in model.objective.signals)
    ]
    techniques = {technique for rule in rule_models for technique in rule.techniques}

    def ratio(done: int, total: int) -> str:
        return f"{done} of {total}" + (f" ({round(100 * done / total)}%)" if total else "")

    rows: list[tuple[str, str]] = [
        (
            "Threat vectors addressed by an objective",
            ratio(sum(1 for record in threats if record.uuid in addressed), len(threats)),
        ),
        ("Objectives implemented by a rule", ratio(len(objective_done), len(objective_models))),
        (
            "Signals implemented by a rule",
            ratio(sum(1 for signal in signals if signal.uuid in implemented), len(signals)),
        ),
        ("ATT&CK techniques detected by rules", str(len(techniques))),
    ]
    return formatter.table(["Measure", "Value"], [list(row) for row in rows])
