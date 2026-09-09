"""Diagram substring assertions for rendered documentation pages."""

from __future__ import annotations

from tests.test_documentation._snapshot_helpers import (
    github_context,
    load_documentation_bundle,
)

from opentide.documentation.catalog import CoverageGraph
from opentide.documentation.objects.objective import render_objective_page
from opentide.documentation.objects.rule import render_rule_page
from opentide.documentation.objects.threat import render_threat_page


def test_threat_page_contains_chaining_and_coverage_mermaid(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_threat_page(bundle.threat, github_context(tmp_path), bundle.catalog)

    assert "## Chaining" in rendered
    assert "## Coverage" in rendered
    assert "## Related objects" in rendered
    assert "```mermaid" in rendered
    assert "flowchart LR" in rendered
    assert "flowchart TB" in rendered
    assert "-->|preceeds|" in rendered
    assert "-->|covers|" in rendered
    assert 'subgraph "Objectives"' in rendered
    assert 'subgraph "Reconnaissance"' in rendered
    assert "### Chaining details" in rendered
    assert "The following TVM is occuring **AFTER** this TVM object has been performed." in rendered
    assert "Cloud Discovery Follow-up" in rendered
    assert "Shai-Hulud Objective" in rendered
    assert '(["Shai-Hulud Objective"])' in rendered or "Shai-Hulud Objective" in rendered


def test_objective_page_contains_coverage_mermaid(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_objective_page(bundle.objective, github_context(tmp_path), bundle.catalog)

    assert "## Coverage" in rendered
    assert "```mermaid" in rendered
    assert "flowchart TB" in rendered
    assert "-->|implements|" in rendered
    assert 'subgraph "Rules"' in rendered
    assert "Shai-Hulud Sentinel Rule" in rendered
    assert "[Shai-Hulud Sentinel Rule](../Rules/shai-hulud-sentinel-rule.md)" in rendered


def test_rule_page_contains_coverage_when_detection_model_exists(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_rule_page(bundle.rule, github_context(tmp_path), bundle.catalog)

    assert "## Coverage" in rendered
    assert "```mermaid" in rendered
    assert "-->|covers|" in rendered
    assert "[Shai-Hulud Objective](../Objectives/shai-hulud-objective.md)" in rendered


def test_rule_page_omits_coverage_when_catalog_has_none(tmp_path) -> None:
    bundle = load_documentation_bundle()
    bundle.catalog.coverage_graph.side_effect = lambda _uuid: CoverageGraph()
    bundle.catalog.related_entries.side_effect = lambda _uuid, direction="both": []
    rendered = render_rule_page(bundle.rule, github_context(tmp_path), bundle.catalog)

    assert "## Coverage" not in rendered
    assert "## Relations" not in rendered
    assert "## Related objects" not in rendered
    assert "```mermaid" not in rendered


def test_objective_page_relations_fallback_is_not_titled_coverage(tmp_path) -> None:
    bundle = load_documentation_bundle()
    bundle.catalog.coverage_graph.side_effect = lambda _uuid: CoverageGraph()
    rendered = render_objective_page(bundle.objective, github_context(tmp_path), bundle.catalog)

    assert "## Coverage" not in rendered
    assert "## Relations" in rendered
    assert "## Related objects" in rendered
    assert "```mermaid" in rendered
