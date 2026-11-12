"""Index pages: one per object folder, and the catalogue overview at the root.

A folder index is a sortable table of its objects with the facts a reader
scans for: a rule's severity and where it deploys at which status, an
objective's signals and rules, a threat's kill chain and detection coverage.
The root page summarises the catalogue: how many objects of each family,
how many rules sit at each status on each platform, and how much of the
threat landscape is covered.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import landscape_diagram, render_diagram
from opentide.documentation.facts.deployment import StatusDefinition
from opentide.documentation.facts.platforms import platform_label
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.links import (
    FOLDER_BY_SCOPE,
    page_href,
    page_slug,
    render_link,
)
from opentide.documentation.markdown.page import GENERATED_NOTICE, Page, join, section
from opentide.documentation.markdown.text import inline_code, join_lines, plural, table_cell
from opentide.documentation.publish.writer import write_page
from opentide.documentation.types import DocumentRecord, DocumentScope, PublishTarget
from opentide.documentation.vocabulary import enrich, vocabulary_order
from opentide.generation import framework as fw
from opentide.generation.errors import rendering
from opentide.models.deployment_enums import StatusStrategy
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
    ("rules", "Detection rules"),
    ("objectives", "Detection objectives"),
    ("threats", "Threat vectors"),
)

#: What each folder holds, on the root index.
_FOLDER_SUMMARIES = {
    "rules": "Deployable queries, where they run and at which status",
    "objectives": "What to detect about a threat, as signals rules implement",
    "threats": "Adversary behaviours, assessed, chained and covered",
}

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
    """Render a folder index page.

    The rules index opens with rules per platform and status; the threat
    vectors index groups its table by kill-chain phase, in kill-chain order.
    """
    scope = records[0].object_type if records else _SCOPE_BY_FOLDER.get(folder)
    from_folder = ""
    if scope is not None:
        from_folder = FOLDER_BY_SCOPE.get(scope, folder)
    elif folder not in {"", "."}:
        from_folder = folder
    headers = ["Name", *_extra_headers(scope), "UUID"]
    if ctx.index_relation_counts:
        headers.append("Related")

    def table(group: Sequence[DocumentRecord]) -> str:
        rows = [_index_row(record, ctx, folder=folder, from_folder=from_folder) for record in group]
        return formatter.index_table(headers, rows)

    parts = [_breadcrumb(ctx), formatter.heading(1, title)]
    if scope in _INTRODUCTIONS:
        count = plural(len(records), _NOUNS[scope])
        parts.append(formatter.paragraph(f"{_INTRODUCTIONS[scope]} {count}."))
    if scope == DocumentScope.rules:
        matrix = _status_matrix(ctx, records)
        if matrix:
            parts += [formatter.heading(2, "Status by platform"), matrix]
            parts.append(formatter.heading(2, "All rules"))
        parts.append(table(records))
    elif scope == DocumentScope.threats and any(_phases(record) for record in records):
        for phase, group in _by_phase(records):
            parts += [formatter.heading(2, phase or "No kill-chain phase"), table(group)]
    else:
        parts.append(table(records))
    parts.append(GENERATED_NOTICE)
    return join(parts) + "\n"


def _index_row(
    record: DocumentRecord, ctx: DocumentationContext, *, folder: str, from_folder: str
) -> list[str]:
    to_folder = FOLDER_BY_SCOPE.get(record.object_type, folder)
    filename = _page_filename(ctx, record)
    href = page_href(from_folder=from_folder, to_folder=to_folder, filename=filename)
    link = render_link(
        ctx.formatter,
        _render_name(record, ctx),
        href,
        wiki=ctx.flavor.value in {"gitlab", "azure_devops"},
    )
    row = [link, *_extra_cells(record), inline_code(record.uuid)]
    if ctx.index_relation_counts:
        with rendering(record.uuid):
            row.append(str(_relation_count(record, ctx)))
    return row


def _breadcrumb(ctx: DocumentationContext) -> str:
    """The way back to the catalogue; Azure DevOps names every index ``README`` alike."""
    if ctx.flavor.value == "azure_devops":
        return ""
    wiki = ctx.flavor.value == "gitlab"
    return ctx.formatter.paragraph(
        render_link(ctx.formatter, "Catalogue", "../README.md", wiki=wiki)
    )


def _phases(record: DocumentRecord) -> list[str]:
    model = record.model
    if not isinstance(model, ThreatVector):
        return []
    killchain = model.threat.killchain
    return [killchain] if isinstance(killchain, str) else list(killchain or [])


def _by_phase(records: Sequence[DocumentRecord]) -> list[tuple[str, list[DocumentRecord]]]:
    """Threats under their first kill-chain phase, phases in kill-chain order, the rest last."""
    order = {phase: index for index, phase in enumerate(vocabulary_order("killchain"))}
    groups: dict[str, list[DocumentRecord]] = {}
    for record in records:
        phases = _phases(record)
        groups.setdefault(phases[0] if phases else "", []).append(record)
    return sorted(
        groups.items(),
        key=lambda item: (not item[0], order.get(item[0], len(order)), item[0]),
    )


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
        row = [render_link(formatter, label, f"{folder_name}/README.md")]
        if ctx.index_relation_counts:
            row.append(str(len(by_folder[folder_name])))
        row.append(_FOLDER_SUMMARIES[folder_name])
        section_rows.append(row)
    headers = ["Section"]
    if ctx.index_relation_counts:
        headers.append("Objects")
    headers.append("Holds")

    page = Page(formatter, "Detection catalogue")
    page.add_lead(
        formatter.paragraph(
            f"{plural(len(threats), 'threat vector')}, "
            f"{plural(len(objectives), 'detection objective')} and "
            f"{plural(len(rules), 'detection rule')}, documented by opentide from the "
            "catalogue's YAML."
        ),
        formatter.index_table(headers, section_rows),
    )
    page.add(section("Threat landscape", _landscape(formatter, objectives, threats)))
    page.add(
        section(
            "Deployment status",
            _status_pie(ctx, rules),
            _status_matrix(ctx, rules),
        )
    )
    page.add(
        section(
            "Coverage",
            _coverage_summary(formatter, rules, objectives, threats),
            children=[
                section("Kill-chain coverage", _killchain_coverage(formatter, objectives, threats))
            ],
        )
    )
    return page.render()


def _landscape(
    formatter: MarkdownFormatter,
    objectives: Sequence[DocumentRecord],
    threats: Sequence[DocumentRecord],
) -> str:
    models = [record.model for record in threats if isinstance(record.model, ThreatVector)]
    return render_diagram(formatter, landscape_diagram(models, addressed=_addressed(objectives)))


def _addressed(objectives: Sequence[DocumentRecord]) -> set[str]:
    """Threat vectors at least one detection objective names."""
    return {
        uuid
        for record in objectives
        if isinstance(record.model, DetectionObjective)
        for uuid in record.model.objective.threats or []
    }


def _status_pie(ctx: DocumentationContext, records: Sequence[DocumentRecord]) -> str:
    """Platform blocks by status, as a Mermaid pie chart."""
    counts: dict[str, int] = {}
    for record in records:
        statuses = getattr(record.model, "platform_statuses", None)
        if isinstance(statuses, dict):
            for status in statuses.values():
                counts[status] = counts.get(status, 0) + 1
    if not counts:
        return ""
    definitions = list(ctx.environment.statuses())
    lifecycle = [status.name for status in definitions]
    ordered = [name for name in lifecycle if name in counts]
    ordered += sorted(set(counts) - set(ordered))
    # Mermaid draws slices largest first, in a stable order, and colours them
    # pie1, pie2... in that order: sort the same way so each colour lands on its status.
    ordered.sort(key=lambda name: -counts[name])
    colours = _status_colours(definitions)
    theme = {
        f"pie{index}": colours.get(name, _UNKNOWN_COLOUR) for index, name in enumerate(ordered, 1)
    }
    theme |= {"pieStrokeColor": "#ffffff", "pieOuterStrokeWidth": "0px"}
    init = json.dumps({"themeVariables": theme, "pie": {"useWidth": 640}}, separators=(",", ":"))
    lines = [f"%%{{init: {init}}}%%", "pie showData title Platform blocks by status"]
    lines += [f'    "{name.replace(chr(34), chr(39))}" : {counts[name]}' for name in ordered]
    return ctx.formatter.mermaid_fence("\n".join(lines))


#: Slice colours by status strategy, lightest first: grey never deploys, amber
#: is preview, blue is both runs, green is release, red is retiring.
_STRATEGY_COLOURS: dict[StatusStrategy, tuple[str, ...]] = {
    StatusStrategy.INERT: ("#d0d5dd", "#98a2b3", "#667085"),
    StatusStrategy.PREVIEW: ("#fedf89", "#fec84b", "#fdb022", "#f79009"),
    StatusStrategy.UNIVERSAL: ("#84caff", "#2e90fa"),
    StatusStrategy.RELEASE: ("#6ce9a6", "#12b76a", "#039855"),
    StatusStrategy.DISABLEMENT: ("#fda29b", "#f97066"),
    StatusStrategy.DELETION: ("#d92d20", "#b42318"),
}
_UNKNOWN_COLOUR = "#475467"


def _status_colours(definitions: Sequence[StatusDefinition]) -> dict[str, str]:
    """A colour per configured status: its strategy's hue, deeper later in the lifecycle."""
    colours: dict[str, str] = {}
    for strategy, palette in _STRATEGY_COLOURS.items():
        names = [status.name for status in definitions if status.strategy is strategy]
        offset = max(len(palette) - len(names), 0)
        for index, name in enumerate(names):
            colours[name] = palette[min(offset + index, len(palette) - 1)]
    return colours


def _killchain_coverage(
    formatter: MarkdownFormatter,
    objectives: Sequence[DocumentRecord],
    threats: Sequence[DocumentRecord],
) -> str:
    """Per kill-chain phase: its threat vectors, and how many an objective addresses."""
    addressed = _addressed(objectives)
    rows: list[list[str]] = []
    for phase, group in _by_phase(threats):
        done = sum(1 for record in group if record.uuid in addressed)
        share = f"{round(100 * done / len(group))}%" if group else "-"
        rows.append([phase or "*No phase*", str(len(group)), str(done), share])
    if not rows:
        return ""
    return formatter.table(
        ["Kill-chain phase", "Threat vectors", "Addressed by an objective", "Coverage"], rows
    )


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
