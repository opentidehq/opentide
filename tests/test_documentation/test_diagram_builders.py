from __future__ import annotations

from unittest.mock import MagicMock

from opentide.documentation.catalog import (
    CoverageEdge,
    CoverageGraph,
    CoverageNode,
    DiagramEntry,
    DocumentationCatalog,
)
from opentide.documentation.diagram.builders import (
    render_chaining_diagram,
    render_coverage_diagram,
    render_relations_diagram,
)
from opentide.documentation.format.azure_devops import AzureDevOpsFormatter
from opentide.documentation.format.github import GitHubFormatter


def _catalog(
    *,
    related: list[DiagramEntry] | None = None,
    chain: list[DiagramEntry] | None = None,
) -> DocumentationCatalog:
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.related_entries.return_value = related or []
    catalog.chaining_entries.return_value = chain or []
    catalog.chaining_network.return_value = CoverageGraph()
    catalog.coverage_graph.return_value = CoverageGraph()
    catalog.resolve_name.side_effect = lambda uuid: f"name-{uuid[:8]}"
    return catalog


def test_render_relations_diagram_github() -> None:
    formatter = GitHubFormatter()
    catalog = _catalog(
        related=[
            DiagramEntry(
                uuid="00000000-0000-4000-8000-000000000002",
                relation="objective",
            )
        ]
    )
    diagram = render_relations_diagram(
        formatter,
        catalog,
        uuid="00000000-0000-4000-8000-000000000001",
        name="Root",
    )
    assert "```mermaid" in diagram
    assert "flowchart TB" in diagram
    assert "Root" in diagram
    assert 'subgraph "Objective"' in diagram
    assert "-->|objective|" in diagram
    assert '(["name-00000000"])' in diagram or "name-00000000" in diagram


def test_render_relations_diagram_azure_uses_graph() -> None:
    formatter = AzureDevOpsFormatter()
    catalog = _catalog(
        related=[
            DiagramEntry(
                uuid="00000000-0000-4000-8000-000000000002",
                relation="objective",
            )
        ]
    )
    diagram = render_relations_diagram(
        formatter,
        catalog,
        uuid="00000000-0000-4000-8000-000000000001",
        name="Root",
    )
    assert "::: mermaid" in diagram
    assert "graph TB" in diagram
    assert "flowchart" not in diagram
    assert "subgraph" not in diagram


def test_render_chaining_diagram_linear() -> None:
    formatter = GitHubFormatter()
    catalog = _catalog(
        chain=[
            DiagramEntry(uuid="step-a", relation="preceeds"),
            DiagramEntry(uuid="step-b", relation="enabled"),
        ]
    )
    diagram = render_chaining_diagram(
        formatter,
        catalog,
        uuid="threat-uuid",
        name="Threat",
    )
    assert "flowchart LR" in diagram
    assert "step-a" in diagram
    assert "-->|preceeds|" in diagram


def test_render_chaining_diagram_empty_when_no_chain() -> None:
    formatter = GitHubFormatter()
    catalog = _catalog(chain=[])
    catalog.chaining_network.return_value = CoverageGraph()
    assert render_chaining_diagram(formatter, catalog, uuid="x", name="X") == ""


def test_render_coverage_diagram_uses_typed_shapes() -> None:
    formatter = GitHubFormatter()
    graph = CoverageGraph(
        nodes=[
            CoverageNode("t1", "Threat One", "threat"),
            CoverageNode("o1", "Objective One", "objective"),
            CoverageNode("s1", "Signal One", "signal"),
            CoverageNode("r1", "Rule One", "rule"),
        ],
        edges=[
            CoverageEdge("t1", "o1", "covers"),
            CoverageEdge("o1", "s1", None),
            CoverageEdge("s1", "r1", "implements"),
        ],
    )
    diagram = render_coverage_diagram(formatter, graph, current_uuid="o1")
    assert "flowchart TB" in diagram
    assert 'subgraph "Threats"' in diagram
    assert 'subgraph "Rules"' in diagram
    assert 'subgraph "Signals"' in diagram
    assert "-->|covers|" in diagram
    assert "{{" in diagram
    assert '(("Signal One"))' in diagram or "Signal One" in diagram


def test_render_coverage_diagram_skips_unknown_objects() -> None:
    formatter = GitHubFormatter()
    assert render_coverage_diagram(formatter, object(), current_uuid="x") == ""
    assert render_coverage_diagram(formatter, CoverageGraph(), current_uuid="x") == ""
