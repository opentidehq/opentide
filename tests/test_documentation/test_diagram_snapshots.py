"""Diagram substring assertions for rendered documentation pages."""

from __future__ import annotations

from tests.test_documentation._snapshot_helpers import (
    github_context,
    load_documentation_bundle,
)

from opentide.documentation.objects.objective import render_objective_page
from opentide.documentation.objects.rule import render_rule_page
from opentide.documentation.objects.threat import render_threat_page


def test_threat_page_contains_chaining_and_relations_mermaid(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_threat_page(bundle.threat, github_context(tmp_path), bundle.catalog)

    assert "## Chaining" in rendered
    assert "## Relations" in rendered
    assert "```mermaid" in rendered
    assert "flowchart LR" in rendered
    assert "flowchart TB" in rendered
    assert "-->|preceeds|" in rendered
    assert "-->|objective|" in rendered
    assert 'subgraph "Objective"' in rendered
    assert "### Chaining details" in rendered
    assert "The following TVM is occuring **AFTER** this TVM object has been performed." in rendered
    assert "Cloud Discovery Follow-up" in rendered
    assert "Shai-Hulud Objective" in rendered


def test_objective_page_contains_relations_mermaid(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_objective_page(bundle.objective, github_context(tmp_path), bundle.catalog)

    assert "## Relations" in rendered
    assert "```mermaid" in rendered
    assert "flowchart TB" in rendered
    assert "-->|rule|" in rendered
    assert 'subgraph "Rule"' in rendered
    assert "Shai-Hulud Sentinel Rule" in rendered


def test_rule_page_omits_relations_when_catalog_has_none(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_rule_page(bundle.rule, github_context(tmp_path), bundle.catalog)

    assert "## Relations" not in rendered
    assert "```mermaid" not in rendered
