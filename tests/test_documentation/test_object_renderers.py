"""Object renderers: section order, empty sections and per-flavor layout."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from tests.test_documentation._snapshot_helpers import context, load_documentation_bundle

from opentide.documentation.catalog import CoverageGraph, DocumentationCatalog
from opentide.documentation.objects.objective import ObjectiveRenderer, render_objective_page
from opentide.documentation.objects.rule import render_rule_page
from opentide.documentation.objects.threat import ThreatRenderer, render_threat_page
from opentide.documentation.types import DocumentFlavor
from opentide.loading.objective_loader import load_objective_from_dict
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector


def _headings(markdown: str, level: int = 2) -> list[str]:
    prefix = "#" * level + " "
    return [line[len(prefix) :] for line in markdown.splitlines() if line.startswith(prefix)]


def _empty_catalog() -> DocumentationCatalog:
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.rules = []
    catalog.coverage_graph.return_value = CoverageGraph()
    catalog.chaining_network.return_value = CoverageGraph()
    catalog.chaining_entries.return_value = []
    catalog.related_entries.return_value = []
    catalog.rules_for_signal.return_value = []
    catalog.resolve_record.return_value = None
    catalog.resolve_signal.return_value = None
    catalog.resolve_name.side_effect = lambda uuid: uuid
    return catalog


def test_rule_page_reads_from_overview_to_metadata(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_rule_page(bundle.rule, context(tmp_path), bundle.catalog)
    assert _headings(rendered) == [
        "Deployment",
        "Platform configuration",
        "Response",
        "ATT&CK techniques",
        "Detection coverage",
        "Metadata",
    ]
    lead = rendered.split("**On this page:**")[0]
    assert lead.startswith(
        "[Catalogue](../README.md) / [Detection rules](README.md)\n\n"
        "# Shai-Hulud Sentinel Rule\n\n"
        "*Detection rule · `rule::1.0` · version 1 · modified 2026-01-02 · TLP:CLEAR*\n\n"
        "Detects suspicious cloud data gathering"
    )
    assert "| Severity | High |" in lead
    assert "| Platforms | Microsoft Sentinel: `STAGING` (PREVIEW runs) |" in lead
    assert rendered.rstrip().endswith("this page is rewritten on every run. -->")


def test_rule_page_states_tenants_and_remote_ids(tmp_path) -> None:
    bundle = load_documentation_bundle()
    rendered = render_rule_page(bundle.rule, context(tmp_path), bundle.catalog)
    assert "| Microsoft Sentinel | `STAGING` | PREVIEW runs | `staging` | yes |" in rendered
    assert "- `STAGING` (strategy `PREVIEW`): Under test on the staging tenant" in rendered
    # The fixture's block sets no schema, so the summary line names none.
    summary = "Status `STAGING` · deployed by PREVIEW runs · tenants: `staging`"
    assert f"### Microsoft Sentinel\n\n{summary}\n" in rendered
    assert (
        "| Microsoft Sentinel | `staging`<br>Pre-production workspace | PREVIEW runs "
        "| `rule-7f3a` |" in rendered
    )
    assert (
        "| Microsoft Sentinel | `production`<br>Production workspace "
        "| no run: the tenant takes RELEASE runs only | - |" in rendered
    )


@pytest.mark.parametrize("flavor", list(DocumentFlavor))
def test_every_flavor_renders_the_rule_page(tmp_path, flavor: DocumentFlavor) -> None:
    bundle = load_documentation_bundle()
    rendered = render_rule_page(bundle.rule, context(tmp_path, flavor), bundle.catalog)
    assert "## Platform configuration" in rendered
    native_toc = flavor in {DocumentFlavor.gitlab, DocumentFlavor.azure_devops}
    assert ("[[_TOC_]]" in rendered) is native_toc
    assert ("**On this page:**" in rendered) is not native_toc
    # Azure DevOps names every index README alike, so its pages have no breadcrumb.
    assert ("[Catalogue]" in rendered) is (flavor is not DocumentFlavor.azure_devops)
    fence = "::: mermaid" if flavor is DocumentFlavor.azure_devops else "```mermaid"
    assert fence in rendered
    assert rendered.endswith("\n") and not rendered.endswith("\n\n")


def test_a_rule_without_platforms_says_so(tmp_path, rule_payload: dict[str, Any]) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    rendered = render_rule_page(rule, context(tmp_path), _empty_catalog())
    assert "# Test rule" in rendered
    assert "> [!NOTE]\n> This rule has no platform configuration" in rendered
    assert "## Platform configuration" not in rendered
    assert "| UUID | `00000000-0000-4000-8000-000000000001` |" in rendered


def test_an_uncovered_threat_is_flagged(tmp_path, metadata: dict[str, Any]) -> None:
    threat = ThreatVector.from_yaml_dict(
        {
            "name": "Credential Access",
            "criticality": "High",
            "metadata": {**metadata, "schema": "threat::1.0"},
            "threat": {
                "description": "Steals credentials",
                "severity": "High",
                "impact": ["Data Breach"],
                "leverage": ["High"],
                "viability": "High",
                "terrain": "Endpoint workstations and user devices.",
                "surface": ["OS::Windows::Desktop"],
                "mitre_attack": ["T1003"],
            },
        }
    )
    rendered = ThreatRenderer(context(tmp_path), _empty_catalog()).render(threat)
    assert "> [!WARNING]\n> No detection objective addresses this threat vector yet." in rendered
    assert "| Detection coverage | None |" in rendered
    assert "## Chaining" not in rendered


def test_objective_page_lists_its_parts(tmp_path, metadata: dict[str, Any]) -> None:
    objective = load_objective_from_dict(
        {
            "name": "Detect lateral movement",
            "metadata": {**metadata, "schema": "objective::1.0"},
            "objective": {
                "priority": "High",
                "type": "Threat",
                "description": "Find lateral movement",
                "composition": {"strategy": "synergetic", "description": "compose"},
                "signals": [],
            },
        }
    )
    rendered = ObjectiveRenderer(context(tmp_path), _empty_catalog()).render(objective)
    # The description is the page's lead, not a section.
    assert _headings(rendered) == ["Composition", "Metadata"]
    assert "*Detection objective · `objective::1.0`" in rendered
    assert "\nFind lateral movement\n" in rendered
    assert "| Detection rules | 0 rules |" in rendered


def test_render_page_helpers_delegate_to_renderer() -> None:
    threat = MagicMock()
    objective = MagicMock()
    ctx = MagicMock()
    catalog = MagicMock()
    with (
        patch(
            "opentide.documentation.objects.threat.ThreatRenderer.render",
            return_value="threat-page",
        ) as mock_threat,
        patch(
            "opentide.documentation.objects.objective.ObjectiveRenderer.render",
            return_value="objective-page",
        ) as mock_objective,
    ):
        assert render_threat_page(threat, ctx, catalog) == "threat-page"
        assert render_objective_page(objective, ctx, catalog) == "objective-page"
    mock_threat.assert_called_once()
    mock_objective.assert_called_once()
