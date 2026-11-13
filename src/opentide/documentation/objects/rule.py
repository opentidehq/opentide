"""Rule object renderer."""

from __future__ import annotations

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import deployment_diagram, render_diagram
from opentide.documentation.diagram.model import NodeKind
from opentide.documentation.facts.deployment import rule_deployments
from opentide.documentation.markdown.page import section
from opentide.documentation.objects.base import ObjectRenderer
from opentide.documentation.parts import common
from opentide.documentation.parts import rule as parts
from opentide.models.rule import DetectionRule


class RuleRenderer(ObjectRenderer):
    """Render detection rules to markdown.

    Reading order: what the rule is (overview, description), where it runs
    (deployment), what it runs (platform configuration), what an analyst does
    with its alert (response), then context (ATT&CK, coverage, provenance).
    """

    folder = "rules"
    kind = NodeKind.rule
    noun = "Detection rule"
    index_title = "Detection rules"

    def render(self, obj: DetectionRule) -> str:
        rule = obj
        deployments = rule_deployments(rule, self.ctx.environment)
        page = self.page(rule.name, rule.metadata, rule.description)
        page.add_lead(parts.overview(rule, deployments, self.links))
        deployment_map = deployment_diagram(
            rule.metadata.uuid, name=rule.name, deployments=deployments
        )
        page.add(
            section(
                "Deployment",
                parts.deployment_body(deployments, self.formatter),
                render_diagram(self.formatter, deployment_map),
                children=[
                    section("Tenant targeting", parts.tenants_body(deployments, self.formatter))
                ],
            )
        )
        page.add(
            section(
                "Platform configuration",
                children=parts.configuration_sections(rule, self.formatter, deployments),
            )
        )
        page.add(section("Response", parts.response_body(rule, self.formatter)))
        page.add(section("ATT&CK techniques", common.attack_table(rule.techniques, self.formatter)))
        page.add(self.coverage_section(rule.metadata.uuid, rule.name))
        page.add(self.references_section(rule.references))
        page.add(self.metadata_section(rule.metadata))
        return page.render()


def render_rule_page(
    rule: DetectionRule,
    ctx: DocumentationContext,
    catalog: DocumentationCatalog,
) -> str:
    """Render markdown for a rule object."""
    return RuleRenderer(ctx, catalog).render(rule)
