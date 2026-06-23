from __future__ import annotations

from unittest.mock import MagicMock

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.diagram.builders import (
    render_chaining_diagram,
    render_relations_diagram,
)
from opentide.documentation.format.azure_devops import AzureDevOpsFormatter
from opentide.documentation.format.github import GitHubFormatter


def _catalog(
    *,
    related: list[str] | None = None,
    chain: list[str] | None = None,
) -> DocumentationCatalog:
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.related_uuids.return_value = related or []
    catalog.chaining_uuids.return_value = chain or []
    catalog.resolve_name.side_effect = lambda uuid: f"name-{uuid[:8]}"
    return catalog


def test_render_relations_diagram_github() -> None:
    formatter = GitHubFormatter()
    catalog = _catalog(related=["00000000-0000-4000-8000-000000000002"])
    diagram = render_relations_diagram(
        formatter,
        catalog,
        uuid="00000000-0000-4000-8000-000000000001",
        name="Root",
    )
    assert "```mermaid" in diagram
    assert "flowchart TB" in diagram
    assert "Root" in diagram


def test_render_relations_diagram_azure_uses_graph() -> None:
    formatter = AzureDevOpsFormatter()
    catalog = _catalog(related=["00000000-0000-4000-8000-000000000002"])
    diagram = render_relations_diagram(
        formatter,
        catalog,
        uuid="00000000-0000-4000-8000-000000000001",
        name="Root",
    )
    assert "::: mermaid" in diagram
    assert "graph TB" in diagram
    assert "flowchart" not in diagram


def test_render_chaining_diagram_linear() -> None:
    formatter = GitHubFormatter()
    catalog = _catalog(chain=["step-a", "step-b"])
    diagram = render_chaining_diagram(
        formatter,
        catalog,
        uuid="threat-uuid",
        name="Threat",
    )
    assert "flowchart LR" in diagram
    assert "step-a" in diagram


def test_render_chaining_diagram_empty_when_no_chain() -> None:
    formatter = GitHubFormatter()
    catalog = _catalog(chain=[])
    assert render_chaining_diagram(formatter, catalog, uuid="x", name="X") == ""
