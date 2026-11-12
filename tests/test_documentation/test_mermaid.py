"""Mermaid rendering: ids, escaping, link styles and the legend."""

from __future__ import annotations

from opentide.documentation.diagram.mermaid import MermaidDialect, legend, render_mermaid
from opentide.documentation.diagram.model import Diagram, Lane, Link, LinkStyle, Node, NodeKind
from opentide.documentation.diagram.sanitize import edge_label, node_label, wrap


def _diagram() -> Diagram:
    diagram = Diagram(title="T", description="D")
    diagram.add_node(Node("u-1", 'Gather (Azure) "victim" data', NodeKind.threat, focus=True))
    diagram.add_node(Node("u-2", "end", NodeKind.rule, caption="STAGING"))
    diagram.add_link(Link("u-1", "u-2", label="feeds | into"))
    return diagram


def test_ids_are_short_typed_and_never_a_reserved_word() -> None:
    source = render_mermaid(_diagram(), MermaidDialect())
    assert 'thr1{{"Gather (Azure) #quot;victim#quot;<br>data"}}' in source
    assert 'rul1["end<br>STAGING"]' in source
    assert 'thr1 -->|"feeds #124; into"| rul1' in source
    assert "u-1" not in source


def test_labels_keep_their_punctuation_as_entity_codes() -> None:
    assert node_label('C# <b> "x" `y`', width=0) == "C#35; #lt;b#gt; #quot;x#quot; #96;y#96;"
    assert edge_label("a|b") == "a#124;b"
    assert node_label("") == "-"


def test_wrap_breaks_on_words_and_keeps_long_words_whole() -> None:
    assert wrap("one two three", 7) == ["one two", "three"]
    assert wrap("supercalifragilistic word", 5) == ["supercalifragilistic", "word"]


def test_link_styles_and_bidirectional_arrows() -> None:
    diagram = Diagram(title="T")
    for key in "abcd":
        diagram.add_node(Node(key, key, NodeKind.threat))
    diagram.add_link(Link("a", "b", style=LinkStyle.thick))
    diagram.add_link(Link("b", "c", style=LinkStyle.dotted, bidirectional=True))
    diagram.add_link(Link("c", "d", bidirectional=True))
    source = render_mermaid(diagram, MermaidDialect())
    assert "thr1 ==> thr2" in source
    assert "thr2 <-.-> thr3" in source
    assert "thr3 <--> thr4" in source


def test_links_are_deduplicated_and_dangling_ones_dropped() -> None:
    diagram = Diagram(title="T")
    diagram.add_node(Node("a", "A", NodeKind.threat))
    diagram.add_node(Node("b", "B", NodeKind.threat))
    diagram.add_link(Link("a", "b", "x", bidirectional=True))
    diagram.add_link(Link("b", "a", "x"))
    diagram.add_link(Link("a", "b", "x"))
    diagram.add_link(Link("a", "missing"))
    diagram.add_link(Link("a", "a"))
    assert len(diagram.links) == 1


def test_a_focus_node_replaces_a_plain_one() -> None:
    diagram = Diagram(title="T")
    diagram.add_node(Node("a", "A", NodeKind.rule))
    diagram.add_node(Node("a", "A", NodeKind.rule, focus=True))
    diagram.add_node(Node("a", "A", NodeKind.rule))
    assert diagram.nodes["a"].focus


def test_lanes_become_subgraphs_and_nodes_are_placed_once() -> None:
    diagram = _diagram()
    diagram.lanes = [Lane("Phase (1)", ("u-1", "missing")), Lane("Again", ("u-1",))]
    source = render_mermaid(diagram, MermaidDialect())
    assert 'subgraph lane1["Phase (1)"]' in source
    assert "lane2" not in source
    assert source.count("thr1{{") == 1
    assert "style lane1 fill:transparent" in source


def test_styles_name_each_kind_and_the_focus() -> None:
    source = render_mermaid(_diagram(), MermaidDialect())
    assert "classDef threat fill:#fdecea" in source
    assert "class thr1 threat" in source
    assert "class thr1 focus" in source
    assert "classDef objective" not in source


def test_plain_dialect_writes_only_what_old_mermaid_parses() -> None:
    diagram = _diagram()
    diagram.lanes = [Lane("Delivery", ("u-1",), caption_fallback=True)]
    source = render_mermaid(diagram, MermaidDialect("graph", False, False, False))
    assert source.splitlines()[0] == "graph LR"
    assert 'thr1{{"Gather (Azure) #quot;victim#quot;<br>data<br>Delivery"}}' in source
    for feature in ("subgraph", "classDef", "class ", "style ", "accTitle"):
        assert feature not in source


def test_accessibility_lines_carry_title_and_description() -> None:
    lines = render_mermaid(_diagram(), MermaidDialect()).splitlines()
    assert lines[1:3] == ["    accTitle: T", "    accDescr: D"]


def test_legend_names_the_shapes_and_line_styles_drawn() -> None:
    diagram = _diagram()
    diagram.link_legend[LinkStyle.solid] = "sequence"
    diagram.link_legend[LinkStyle.dotted] = "unused"
    text = legend(diagram, MermaidDialect())
    assert text == (
        "*Shapes:* hexagon = threat vector; rectangle = detection rule; "
        "bold outline = this page. *Lines:* solid line = sequence."
    )
    assert "bold outline" not in legend(diagram, MermaidDialect(styles=False))
