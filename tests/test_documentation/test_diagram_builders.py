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
    deployment_diagram,
    landscape_diagram,
    relations_diagram,
    render_diagram,
)
from opentide.documentation.diagram.model import LinkStyle, NodeKind
from opentide.documentation.facts.deployment import (
    PlatformDeployment,
    StatusDefinition,
    TenantTarget,
)
from opentide.documentation.format.azure_devops import AzureDevOpsFormatter
from opentide.documentation.format.github import GitHubFormatter
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.threat import ThreatVector


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


def test_deployment_map_draws_platforms_and_the_tenants_each_run_reaches() -> None:
    preview = StatusDefinition("STAGING", "", StatusStrategy.PREVIEW)
    inert = StatusDefinition("DRAFT", "", StatusStrategy.INERT)
    deployments = [
        PlatformDeployment(
            "sentinel",
            "Microsoft Sentinel",
            True,
            "STAGING",
            preview,
            (StatusStrategy.PREVIEW,),
            "all",
            targets=(
                TenantTarget("staging", runs=(StatusStrategy.PREVIEW,), remote_id="42"),
                TenantTarget("prod", accepts=(StatusStrategy.RELEASE,)),
            ),
        ),
        PlatformDeployment("splunk", "Splunk", True, "DRAFT", inert, (), "all"),
    ]
    diagram = deployment_diagram("r1", name="Rule One", deployments=deployments)
    assert diagram is not None
    assert [lane.title for lane in diagram.lanes] == ["Detection rule", "Platforms", "Tenants"]
    rendered = render_diagram(GitHubFormatter(), diagram)
    assert 'plt1[("Microsoft Sentinel<br>STAGING")]' in rendered
    assert 'ten1[["staging<br>id 42"]]' in rendered
    assert 'plt1 -->|"PREVIEW"| ten1' in rendered
    assert "plt1 -.-> ten2" in rendered
    # A status no run deploys is drawn dotted, and the legend says so.
    assert "rul1 -.-> plt2" in rendered
    assert "subroutine box = tenant" in rendered
    assert "dotted line = not deployed" in rendered
    assert deployment_diagram("r1", name="Rule One", deployments=[]) is None


def test_landscape_lanes_every_threat_and_marks_the_uncovered(metadata: dict) -> None:
    def threat(uuid: str, phase: str, chaining: list[dict[str, str]]) -> ThreatVector:
        return ThreatVector.from_yaml_dict(
            {
                "name": f"Threat {uuid}",
                "criticality": "High",
                "metadata": {**metadata, "uuid": uuid, "schema": "threat::1.0"},
                "threat": {
                    "description": "d",
                    "severity": "Moderate incident",
                    "impact": ["Data Breach"],
                    "leverage": ["Spoofing"],
                    "viability": "Likely",
                    "terrain": "t",
                    "surface": ["Entra ID"],
                    "mitre_attack": ["T1078"],
                    "killchain": phase,
                    "chaining": chaining,
                },
            }
        )

    threats = [
        threat("a", "Collection", [{"vector": "b", "relation": "succeeds"}]),
        threat("b", "Delivery", [{"vector": "elsewhere", "relation": "preceeds"}]),
    ]
    diagram = landscape_diagram(threats, addressed={"a"})
    assert diagram is not None
    assert [lane.title for lane in diagram.lanes] == ["Delivery", "Collection"]
    assert [(link.source, link.target) for link in diagram.links] == [("b", "a")]
    rendered = render_diagram(GitHubFormatter(), diagram)
    assert 'thr2{{"Threat b<br>not covered"}}' in rendered
    assert "class thr2 gap" in rendered
    assert "dashed outline = no detection objective" in rendered
    assert landscape_diagram(threats[:1], addressed=set()) is None


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


def test_killchain_stages_follow_the_unified_kill_chain() -> None:
    from opentide.documentation.vocabulary import killchain_stage, killchain_stages

    stages = killchain_stages()
    assert [stage for stage, _ in stages] == [
        "Initial Foothold",
        "Network Propagation",
        "Action on Objectives",
    ]
    assert stages[1][1][:2] == ["Pivoting", "Discovery"]
    assert sum(len(phases) for _, phases in stages) == 18
    assert killchain_stage("Credential Access") == "Network Propagation"
    assert killchain_stage("Not a phase") == ""


def test_killchain_coverage_colours_each_phase_by_its_threats() -> None:
    from opentide.documentation.diagram.builders import killchain_coverage_diagram
    from opentide.documentation.diagram.model import Tone

    diagram = killchain_coverage_diagram(
        {"Delivery": [False], "Collection": [True, False], "Persistence": [True]}
    )
    assert diagram is not None
    nodes = {node.label: node for node in diagram.nodes.values()}
    assert (nodes["Delivery"].tone, nodes["Delivery"].caption) == (Tone.uncovered, "0 of 1 covered")
    assert (nodes["Collection"].tone, nodes["Collection"].caption) == (
        Tone.partial,
        "1 of 2 covered",
    )
    assert nodes["Persistence"].tone is Tone.covered
    assert (nodes["Impact"].tone, nodes["Impact"].caption) == (Tone.idle, "")
    assert [lane.direction for lane in diagram.lanes] == ["LR", "LR", "LR"]
    rendered = render_diagram(GitHubFormatter(), diagram)
    assert "flowchart TB" in rendered
    assert "        direction LR" in rendered
    assert "    lane1 --> lane2 --> lane3" in rendered
    assert "classDef uncovered fill:#fef3f2" in rendered
    assert "*Colours:* green = every threat vector addressed" in rendered
    assert killchain_coverage_diagram({}) is None


def test_azure_kill_chain_links_the_stages_through_their_phases() -> None:
    from opentide.documentation.diagram.builders import killchain_coverage_diagram

    diagram = killchain_coverage_diagram({"Delivery": [True]})
    rendered = render_diagram(AzureDevOpsFormatter(), diagram)
    assert "subgraph" not in rendered and "direction" not in rendered
    # Command & Control ends the first stage, Pivoting opens the second.
    assert "kc8 --> kc9" in rendered
    assert "kc14 --> kc15" in rendered
    assert "*Colours:*" not in rendered


def test_threat_killchain_marks_its_phase_and_the_chained_threats() -> None:
    from opentide.documentation.diagram.builders import threat_killchain_diagram
    from opentide.documentation.diagram.model import Tone

    diagram = threat_killchain_diagram(
        ["Credential Access"],
        related={"Delivery": ["AiTM phishing"], "Collection": ["Mail theft", "Export"]},
    )
    assert diagram is not None
    nodes = {node.label: node for node in diagram.nodes.values()}
    assert (nodes["Credential Access"].tone, nodes["Credential Access"].caption) == (
        Tone.current,
        "this threat",
    )
    assert nodes["Credential Access"].focus
    assert (nodes["Delivery"].tone, nodes["Delivery"].caption) == (Tone.related, "AiTM phishing")
    assert nodes["Collection"].caption == "Mail theft +1"
    assert nodes["Impact"].tone is None
    assert threat_killchain_diagram(["Unknown phase"], related={}) is None
