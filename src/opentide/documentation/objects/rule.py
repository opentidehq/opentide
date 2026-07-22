"""Rule object renderer."""

from __future__ import annotations

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import render_relations_diagram
from opentide.documentation.objects.base import ObjectRenderer
from opentide.documentation.parts import sections
from opentide.models.rule import DetectionRule


class RuleRenderer(ObjectRenderer):
    """Render detection rules to markdown."""

    def render(self, obj: DetectionRule) -> str:
        rule = obj
        blocks = [
            self.title_block(rule.name),
            sections.render_metadata(rule.metadata, self.formatter),
            sections.render_references(rule.references, self.formatter),
            sections.render_description(rule.description, self.formatter),
            sections.render_rule_status(rule, self.formatter),
            sections.render_techniques(rule.techniques, self.formatter),
            sections.render_detection_model_link(
                rule,
                self.formatter,
                self.catalog,
                uuid_permalinks=self.ctx.uuid_permalinks,
                wiki_links=self.ctx.flavor.value in {"gitlab", "azure_devops"},
            ),
            sections.render_rule_response(rule, self.formatter),
            sections.render_rule_queries(rule, self.formatter),
            self._relations(rule),
        ]
        return self.assemble(blocks)

    def _relations(self, rule: DetectionRule) -> str:
        diagram = render_relations_diagram(
            self.formatter,
            self.catalog,
            uuid=rule.metadata.uuid,
            name=rule.name,
            direction=self.ctx.relations_direction,
        )
        if not diagram:
            return ""
        return self.formatter.heading(2, "Relations") + diagram


def render_rule_page(
    rule: DetectionRule,
    ctx: DocumentationContext,
    catalog: DocumentationCatalog,
) -> str:
    """Render markdown for a rule object."""
    return RuleRenderer(ctx, catalog).render(rule)
