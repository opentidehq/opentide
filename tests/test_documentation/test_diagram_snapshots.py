"""Diagrams and their sections on rendered object pages."""

from __future__ import annotations

from tests.test_documentation._snapshot_helpers import (
    github_context,
    load_documentation_bundle,
)

from opentide.documentation.catalog import CoverageGraph
from opentide.documentation.objects.objective import render_objective_page
from opentide.documentation.objects.rule import render_rule_page
from opentide.documentation.objects.threat import render_threat_page


def test_threat_page_draws_chaining_by_kill_chain_and_detection_coverage(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_threat_page(bundle.threat, github_context(tmp_path), bundle.catalog)

    assert "## Chaining\n\n```mermaid\nflowchart LR\n" in rendered
    assert 'subgraph lane1["Reconnaissance"]' in rendered
    assert 'thr1 -->|"preceeds"| thr2' in rendered
    assert "### Chaining relations" in rendered
    assert (
        "| `preceeds` | Cloud Discovery Follow-up (`00000000-0000-4000-8101-000000000099`) |"
        in rendered
    )
    assert "## Detection coverage" in rendered
    assert 'subgraph lane2["Detection objectives"]' in rendered
    assert 'obj1(["Shai-Hulud Objective"])' in rendered
    assert "### Related objects" in rendered


def test_objective_page_draws_its_coverage(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_objective_page(bundle.objective, github_context(tmp_path), bundle.catalog)

    assert "## Detection coverage" in rendered
    assert 'subgraph lane4["Detection rules"]' in rendered
    assert "sig1 --> rul1" in rendered
    assert "class obj1 focus" in rendered
    assert "[Shai-Hulud Sentinel Rule](../rules/shai-hulud-sentinel-rule.md)" in rendered


def test_rule_page_draws_its_lineage_and_platforms(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_rule_page(bundle.rule, github_context(tmp_path), bundle.catalog)

    assert "## Detection coverage" in rendered
    assert "thr1 --> obj1" in rendered
    assert 'plt1[("Microsoft Sentinel<br>STAGING")]' in rendered
    assert "rul1 --> plt1" in rendered
    assert "[Shai-Hulud Objective](../objectives/shai-hulud-objective.md)" in rendered


def test_rule_page_omits_coverage_when_catalog_has_none(tmp_path) -> None:
    bundle = load_documentation_bundle()
    bundle.catalog.coverage_graph.side_effect = lambda _uuid: CoverageGraph()
    bundle.catalog.related_entries.side_effect = lambda _uuid, direction="both": []
    rendered = render_rule_page(bundle.rule, github_context(tmp_path), bundle.catalog)

    assert "## Detection coverage" not in rendered
    assert "## Relations" not in rendered
    assert "Related objects" not in rendered
    assert "```mermaid" not in rendered


def test_objective_page_relations_fallback_is_not_titled_coverage(tmp_path) -> None:
    bundle = load_documentation_bundle()
    bundle.catalog.coverage_graph.side_effect = lambda _uuid: CoverageGraph()
    rendered = render_objective_page(bundle.objective, github_context(tmp_path), bundle.catalog)

    assert "## Detection coverage" not in rendered
    assert "## Relations\n\n```mermaid" in rendered
    assert "### Related objects" in rendered
