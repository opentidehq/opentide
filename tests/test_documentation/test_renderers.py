from __future__ import annotations

from unittest.mock import MagicMock

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.objects.rule import RuleRenderer
from opentide.documentation.types import DocumentFlavor
from opentide.models.rule import DetectionRule


def test_rule_renderer_uses_context_formatter(rule_payload: dict) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=MagicMock(),
        formatter=formatter_for(DocumentFlavor.github),
    )
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.related_uuids.return_value = []
    md = RuleRenderer(ctx, catalog).render(rule)
    assert "# Test rule" in md
    assert "00000000-0000-4000-8000-000000000001" in md
    assert "## Status" in md
    assert "T1059" in md
