"""Diagram builders: coverage, chaining and relations graphs from the catalogue."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from opentide.documentation.catalog import (
    CoverageEdge,
    CoverageGraph,
    CoverageNode,
    DiagramEntry,
    DocumentationCatalog,
)
from opentide.documentation.diagram.builders import (
    chaining_diagram,
    coverage_diagram,
    relations_diagram,
    render_diagram,
)
from opentide.documentation.diagram.model import LinkStyle, NodeKind
from opentide.documentation.facts.deployment import PlatformDeployment, StatusDefinition
from opentide.documentation.format.azure_devops import AzureDevOpsFormatter
from opentide.documentation.format.github import GitHubFormatter
from opentide.models.deployment_enums import StatusStrategy


def _catalog(
    *,
    related: list[DiagramEntry] | None = None,
    chain: list[DiagramEntry] | None = None,
    network: CoverageGraph | None = None,
    coverage: CoverageGraph | None = None,
) -> DocumentationCatalog:
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.related_entries.return_value = related or []
    catalog.chaining_entries.return_value = chain or []
    catalog.chaining_network.return_value = network or CoverageGraph()
    catalog.coverage_graph.return_value = coverage or CoverageGraph()
    catalog.resolve_name.side_effect = lambda uuid: f"name-{uuid[:8]}"
    return catalog


_COVERAGE = CoverageGraph(
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


def test_coverage_diagram_lanes_run_from_threat_to_rule() -> None:
    diagram = coverage_diagram(_catalog(coverage=_COVERAGE), "o1", name="Objective One")
    assert diagram is not None
    assert [lane.title for lane in diagram.lanes] == [
        "Threat vectors",
        "Detection objectives",
        "Signals",
        "Detection rules",
    ]
    assert [node.key for node in diagram.nodes.values() if node.focus] == ["o1"]
    rendered = render_diagram(GitHubFormatter(), diagram)
    assert "flowchart LR" in rendered
    assert 'thr1{{"Threat One"}}' in rendered
    assert 'sig1(("Signal One"))' in rendered
    assert "thr1 --> obj1" in rendered
    assert "class obj1 focus" in rendered
    assert "accTitle: Detection coverage of Objective One" in rendered
    assert "*Shapes:* hexagon = threat vector" in rendered


def test_coverage_diagram_adds_a_rules_platforms_with_their_status() -> None:
    preview = StatusDefinition("STAGING", "", StatusStrategy.PREVIEW)
    inert = StatusDefinition("DRAFT", "", StatusStrategy.INERT)
    platforms = [
        PlatformDeployment(
            "sentinel",
            "Microsoft Sentinel",
            True,
            "STAGING",
            preview,
            (StatusStrategy.PREVIEW,),
            "all",
        ),
        PlatformDeployment("splunk", "Splunk", True, "DRAFT", inert, (), "all"),
    ]
    diagram = coverage_diagram(
        _catalog(coverage=_COVERAGE), "r1", name="Rule One", platforms=platforms
    )
    assert diagram is not None
    rendered = render_diagram(GitHubFormatter(), diagram)
    assert 'plt1[("Microsoft Sentinel<br>STAGING")]' in rendered
    assert "rul1 --> plt1" in rendered
    # A status no run deploys is drawn dotted, and the legend says so.
    assert "rul1 -.-> plt2" in rendered
    assert "dotted line = a status no run deploys" in rendered


def test_azure_dialect_drops_lanes_styles_and_accessibility() -> None:
    diagram = coverage_diagram(_catalog(coverage=_COVERAGE), "o1", name="Objective One")
    rendered = render_diagram(AzureDevOpsFormatter(), diagram)
    assert rendered.startswith("::: mermaid\ngraph LR\n")
    for feature in ("subgraph", "classDef", "accTitle", "flowchart"):
        assert feature not in rendered
    assert "bold outline" not in rendered


def test_chaining_diagram_draws_every_pair_in_its_from_direction() -> None:
    """``B succeeds A`` is drawn as ``A preceeds B``, merged with A's own declaration."""
    network = CoverageGraph(
        nodes=[
            CoverageNode("a", "Initial Access", "threat", killchain="Delivery"),
            CoverageNode("b", "Execution Step", "threat", killchain="Reconnaissance"),
        ],
        edges=[
            CoverageEdge("a", "b", "preceeds"),
            CoverageEdge("b", "a", "succeeds"),
        ],
    )
    diagram = chaining_diagram(_catalog(network=network), "a", name="Initial Access")
    assert diagram is not None
    assert [(link.source, link.target, link.label) for link in diagram.links] == [
        ("a", "b", "preceeds")
    ]
    # Lanes follow the kill chain, not the order the threats were found in.
    assert [lane.title for lane in diagram.lanes] == ["Reconnaissance", "Delivery"]
    rendered = render_diagram(GitHubFormatter(), diagram)
    assert 'thr1 -->|"preceeds"| thr2' in rendered
    assert "solid line = sequence" in rendered


def test_chaining_families_have_their_own_line_styles() -> None:
    network = CoverageGraph(
        nodes=[CoverageNode(key, key, "threat") for key in ("a", "b", "c", "d")],
        edges=[
            CoverageEdge("a", "b", "implements"),
            CoverageEdge("a", "c", "synergize"),
            CoverageEdge("a", "d", "enabling"),
        ],
    )
    diagram = chaining_diagram(_catalog(network=network), "a", name="a")
    assert diagram is not None
    styles = {
        (link.source, link.target): (link.style, link.bidirectional) for link in diagram.links
    }
    assert styles[("b", "a")] == (LinkStyle.thick, False)
    assert styles[("a", "c")] == (LinkStyle.dotted, True)
    assert styles[("d", "a")] == (LinkStyle.dotted, False)


def test_chaining_without_lanes_shows_the_phase_under_each_threat() -> None:
    network = CoverageGraph(
        nodes=[
            CoverageNode("a", "First", "threat", killchain="Delivery"),
            CoverageNode("b", "Second", "threat"),
        ],
        edges=[CoverageEdge("a", "b", "preceeds")],
    )
    diagram = chaining_diagram(_catalog(network=network), "a", name="First")
    rendered = render_diagram(AzureDevOpsFormatter(), diagram)
    assert 'thr1{{"First<br>Delivery"}}' in rendered
    assert 'thr2{{"Second"}}' in rendered


def test_chaining_falls_back_to_the_threats_own_entries() -> None:
    catalog = _catalog(
        chain=[
            DiagramEntry(uuid="step-a", relation="preceeds"),
            DiagramEntry(uuid="step-b", relation="enabled"),
        ]
    )
    diagram = chaining_diagram(catalog, "threat-uuid", name="Threat")
    assert diagram is not None
    rendered = render_diagram(GitHubFormatter(), diagram)
    assert 'thr2{{"name-step-a"}}' in rendered
    assert '-->|"preceeds"|' in rendered


def test_no_chaining_draws_nothing() -> None:
    assert chaining_diagram(_catalog(), "x", name="X") is None
    assert render_diagram(GitHubFormatter(), None) == ""


def test_relations_diagram_puts_the_object_among_its_neighbours() -> None:
    catalog = _catalog(
        related=[
            DiagramEntry(uuid="obj", object_type="objective", direction="upstream", name="Goal"),
            DiagramEntry(uuid="weird", object_type="unknown"),
        ]
    )
    diagram = relations_diagram(catalog, "rule", name="Root", kind=NodeKind.rule)
    assert diagram is not None
    assert list(diagram.nodes) == ["rule", "obj"]
    assert [(link.source, link.target) for link in diagram.links] == [("obj", "rule")]


@pytest.mark.parametrize("graph", [object(), CoverageGraph()])
def test_coverage_diagram_skips_missing_graphs(graph: object) -> None:
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.coverage_graph.return_value = graph
    assert coverage_diagram(catalog, "x", name="X") is None
