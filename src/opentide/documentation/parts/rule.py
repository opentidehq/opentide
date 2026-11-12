"""Rule sections: overview, deployment, platform configuration and response.

The status, strategy and tenants come from
:mod:`opentide.documentation.facts.deployment`, which reads them as deploy
does; every platform setting comes from
:mod:`opentide.documentation.facts.settings`, which walks the block model.
Nothing here lists platform fields by hand, so a new field or platform is
documented without a change to this module.
"""

from __future__ import annotations

from collections.abc import Sequence

from opentide.core.responders import resolve_responders
from opentide.documentation.facts.deployment import (
    PlatformDeployment,
    StatusDefinition,
    TenantTarget,
)
from opentide.documentation.facts.platforms import PROFILES, TEXT, CodeLanguage, profile_for
from opentide.documentation.facts.settings import Settings, flatten
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.page import Section, join, key_value_table, section
from opentide.documentation.markdown.text import (
    inline_code,
    join_lines,
    table_cell,
)
from opentide.documentation.parts.common import Links, technique_links, vocab_label
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.platform import PlatformConfigBase
from opentide.models.rule import DetectionRule

#: Block keys the deployment table and each platform's summary line already document.
_DEPLOYMENT_KEYS = ("enabled", "status", "tenants", "schema")

#: What a run does to a rule, by the strategy its status maps to.
_RUN_VERBS: dict[StatusStrategy, str] = {
    StatusStrategy.DISABLEMENT: "disables",
    StatusStrategy.DELETION: "deletes",
}


def overview(rule: DetectionRule, deployments: Sequence[PlatformDeployment], links: Links) -> str:
    """The facts a reader needs first: severity, model, techniques, where it runs."""
    formatter = links.formatter
    response = rule.response
    rows = [
        ("Severity", vocab_label("alert_severity", rule.displayed_severity or "")),
        ("Detection model", links.to(rule.detection_model) if rule.detection_model else ""),
        ("ATT&CK", technique_links(rule.techniques, formatter)),
        ("Platforms", join_lines(_platform_summary(item) for item in deployments)),
        ("Playbook", table_cell(response.playbook) if response and response.playbook else ""),
        ("Responders", table_cell(resolve_responders(response) or "") if response else ""),
    ]
    return key_value_table(formatter, rows, headers=("Property", "Value"))


def _platform_summary(deployment: PlatformDeployment) -> str:
    runs = _runs_text(deployment)
    return f"{deployment.label}: {inline_code(deployment.status)} ({runs})"


def deployment_body(deployments: Sequence[PlatformDeployment], formatter: MarkdownFormatter) -> str:
    """Per platform: status, strategy, the runs that act on it and the tenants they reach."""
    if not deployments:
        return formatter.callout(
            "note", "This rule has no platform configuration: no run deploys it anywhere."
        )
    intro = formatter.paragraph(
        "What `opentide deploy` does with this rule: each platform block's status, the runs "
        "that act on it, and the tenants they reach."
    )
    rows = [
        [
            deployment.label,
            inline_code(deployment.status),
            _runs_text(deployment),
            _tenants_text(deployment),
            "yes" if deployment.enabled else "no",
        ]
        for deployment in deployments
    ]
    table = formatter.table(["Platform", "Status", "Deployed by", "Tenants", "Block enabled"], rows)
    return join([intro, table, _status_reference(deployments), *_warnings(deployments, formatter)])


def tenants_body(deployments: Sequence[PlatformDeployment], formatter: MarkdownFormatter) -> str:
    """Every candidate tenant, the runs that reach it and the remote id it holds."""
    rows: list[list[str]] = []
    for deployment in deployments:
        for target in deployment.targets:
            rows.append(_tenant_row(deployment, target))
        for tenant, remote_id in deployment.orphaned_ids.items():
            rows.append(
                [deployment.label, inline_code(tenant), "not targeted", inline_code(remote_id)]
            )
    if not rows:
        return ""
    return formatter.table(["Platform", "Tenant", "Reached by", "Remote ID"], rows)


def _tenant_row(deployment: PlatformDeployment, target: TenantTarget) -> list[str]:
    if target.runs:
        reached = ", ".join(f"{run.name} runs" for run in target.runs)
    elif deployment.runs and target.accepts:
        accepted = " and ".join(run.name for run in target.accepts)
        reached = f"no run: the tenant takes {accepted} runs only"
    elif deployment.runs:
        reached = "no run: the tenant takes none of the rule's runs"
    else:
        reached = "no run: no run deploys this status"
    name = inline_code(target.name)
    if target.description:
        name = f"{name}<br>{table_cell(target.description)}"
    return [deployment.label, name, reached, inline_code(target.remote_id) or "-"]


def _runs_text(deployment: PlatformDeployment) -> str:
    if deployment.definition is None:
        return "unknown status"
    if not deployment.runs:
        return "never deployed"
    verb = _RUN_VERBS.get(deployment.definition.strategy)
    runs = " and ".join(run.name for run in deployment.runs)
    return f"{runs} runs, which {verb} it" if verb else f"{runs} runs"


def _tenants_text(deployment: PlatformDeployment) -> str:
    if deployment.scope == "unknown":
        return "every tenant that is not manual (not configured here)"
    if deployment.scope == "none":
        return "no tenant configured"
    names = [inline_code(target.name) for target in deployment.reached]
    if deployment.scope == "listed" and not deployment.reached:
        names = [inline_code(target.name) for target in deployment.targets]
    if not names:
        return "none"
    prefix = "listed: " if deployment.scope == "listed" else ""
    return prefix + ", ".join(names)


def _status_reference(deployments: Sequence[PlatformDeployment]) -> str:
    """Each status the table uses: its strategy in ``deployment.toml``, and what it means."""
    seen: dict[str, StatusDefinition] = {}
    for deployment in deployments:
        if deployment.definition is not None:
            seen.setdefault(deployment.status, deployment.definition)
    lines = []
    for status, definition in seen.items():
        line = f"- {inline_code(status)} (strategy {inline_code(definition.strategy.name)})"
        if definition.description:
            line += f": {' '.join(definition.description.split())}"
        lines.append(line)
    return "\n".join(lines)


def _warnings(deployments: Sequence[PlatformDeployment], formatter: MarkdownFormatter) -> list[str]:
    notes: list[str] = []
    for deployment in deployments:
        if deployment.platform_enabled is False:
            notes.append(
                f"{deployment.label} is not enabled in this workspace: no run deploys this block."
            )
        if deployment.definition is None:
            notes.append(
                f"{deployment.label}: status {inline_code(deployment.status)} is not defined "
                "in `deployment.toml`, so no run deploys this block."
            )
        if deployment.scope == "none" and deployment.runs:
            notes.append(
                f"{deployment.label} configures no tenant: a run that deploys this block "
                "fails until one is added to the platform file."
            )
        elif deployment.unknown_tenants:
            names = ", ".join(inline_code(name) for name in deployment.unknown_tenants)
            notes.append(f"{deployment.label} has no tenant named {names}.")
    return [formatter.callout("warning", note) for note in notes]


def configuration_sections(
    rule: DetectionRule,
    formatter: MarkdownFormatter,
    deployments: Sequence[PlatformDeployment] = (),
) -> list[Section]:
    """One section per platform block, documenting every setting it holds."""
    if rule.configurations is None:
        return []
    by_platform = {deployment.platform: deployment for deployment in deployments}
    sections: list[Section] = []
    for platform in type(rule.configurations).model_fields:
        block = getattr(rule.configurations, platform, None)
        if isinstance(block, PlatformConfigBase):
            sections.append(platform_section(platform, block, formatter, by_platform.get(platform)))
    return sections


def platform_section(
    platform: str,
    block: PlatformConfigBase,
    formatter: MarkdownFormatter,
    deployment: PlatformDeployment | None = None,
) -> Section:
    profile = profile_for(platform)
    settings = flatten(
        block,
        exclude=_DEPLOYMENT_KEYS,
        code_language=lambda path: profile.language(path, block),
    )
    return section(
        profile.label,
        _block_summary(block, deployment, formatter),
        settings_body(settings, formatter),
    )


def _block_summary(
    block: PlatformConfigBase, deployment: PlatformDeployment | None, formatter: MarkdownFormatter
) -> str:
    """One line on where the block stands: status, runs, tenants, schema."""
    parts = [f"Status {inline_code(block.status)}"]
    if deployment is not None:
        runs = _runs_text(deployment)
        parts.append(f"deployed by {runs}" if deployment.runs else runs)
        parts.append(f"tenants: {_tenants_text(deployment)}")
    if block.schema:
        parts.append(f"schema {inline_code(block.schema)}")
    if not block.enabled:
        parts.append("block disabled")
    return formatter.paragraph(" · ".join(parts))


def settings_body(settings: Settings, formatter: MarkdownFormatter) -> str:
    """Code first (what the rule detects), then the settings table and list tables."""
    parts: list[str] = []
    for item in settings.code:
        language = item.language or TEXT
        caption = f"**{inline_code(item.path)}** ({language.name})"
        if item.description and item.description.rstrip(".") != language.name:
            caption += f": {item.description}"
        parts.append(caption)
        parts.append(formatter.code_block(language.fence, item.code))
    if settings.rows:
        rows = [
            [
                inline_code(row.path),
                row.value + (" *(default)*" if row.default else ""),
                table_cell(row.description) if row.description else "",
            ]
            for row in settings.rows
        ]
        parts.append(formatter.table(["Setting", "Value", "Description"], rows))
    for table in settings.tables:
        caption = f"**{inline_code(table.path)}**"
        if table.description:
            caption += f": {table.description}"
        parts.append(caption)
        parts.append(
            formatter.table(
                [inline_code(column) for column in table.columns], [list(row) for row in table.rows]
            )
        )
    if not parts:
        return formatter.paragraph("The block sets nothing beyond its deployment status.")
    return join(parts)


def response_body(rule: DetectionRule, formatter: MarkdownFormatter) -> str:
    """Alert severity, playbook, responders and the analyst procedure."""
    response = rule.response
    if response is None:
        return ""
    procedure = response.procedure
    rows = [
        ("Alert severity", vocab_label("alert_severity", response.alert_severity)),
        ("Playbook", table_cell(response.playbook or "")),
        # Not vocabulary-labelled: responders are per-organisation configuration.
        ("Responders", table_cell(resolve_responders(response) or "")),
    ]
    parts = [key_value_table(formatter, rows, headers=("Property", "Value"))]
    if procedure is not None:
        parts.append(f"**Analysis**\n\n{procedure.analysis.strip()}")
        if procedure.containment:
            parts.append(f"**Containment**\n\n{procedure.containment.strip()}")
        for search in procedure.searches or []:
            language = _search_language(search.system)
            parts.append(f"**Search: {search.purpose}** ({search.system}, {language.name})")
            parts.append(formatter.code_block(language.fence, search.query.rstrip("\n")))
    return join(parts)


def _search_language(system: str) -> CodeLanguage:
    """The query language of a response search, from the system it names."""
    wanted = system.strip().lower().replace(" ", "_")
    for profile in PROFILES.values():
        names = {profile.key, profile.label.lower().replace(" ", "_")}
        if wanted in names or any(name.startswith(wanted) for name in names):
            primary = profile.languages.get("query")
            if primary is not None:
                return primary
    return TEXT
