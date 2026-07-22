"""Threat and objective documentation renderers."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from opentide.documentation.objects.objective import ObjectiveRenderer, render_objective_page
from opentide.documentation.objects.threat import ThreatRenderer, render_threat_page
from opentide.loading.objective_loader import load_objective_from_dict
from opentide.models.threat import ThreatVector


def _objective_payload(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "Detect lateral movement",
        "metadata": {**metadata, "schema": "objective::1.0"},
        "composition": {"strategy": "synergetic", "description": "compose"},
        "objective": {
            "priority": "High",
            "type": "Threat",
            "description": "Find lateral movement",
            "composition": {"strategy": "synergetic", "description": "compose"},
            "signals": [],
        },
    }


def test_threat_renderer_includes_diagram_sections(metadata: dict[str, Any]) -> None:
    threat = ThreatVector.from_yaml_dict(
        {
            "name": "Credential Access",
            "criticality": "High",
            "metadata": {**metadata, "schema": "threat::1.0"},
            "threat": {
                "description": "Steals credentials",
                "severity": "High",
                "impact": "Data Breach",
                "leverage": "High",
                "viability": "High",
                "terrain": "Endpoint workstations and user devices.",
                "surface": ["Windows::Desktop"],
                "att&ck": ["T1003"],
            },
        }
    )
    ctx = MagicMock()
    ctx.formatter.heading.side_effect = lambda _level, text: f"## {text}\n"
    catalog = MagicMock()
    with (
        patch(
            "opentide.documentation.objects.threat.render_chaining_diagram",
            return_value="chain-diagram",
        ),
        patch(
            "opentide.documentation.objects.threat.render_relations_diagram",
            return_value="relations-diagram",
        ),
        patch(
            "opentide.documentation.objects.threat.sections.render_metadata",
            return_value="meta\n",
        ),
        patch(
            "opentide.documentation.objects.threat.sections.render_threat_body",
            return_value="body\n",
        ),
    ):
        rendered = ThreatRenderer(ctx, catalog).render(threat)
    assert "Credential Access" in rendered
    assert "chain-diagram" in rendered
    assert "relations-diagram" in rendered


def test_objective_renderer_includes_relations(metadata: dict[str, Any]) -> None:
    objective = load_objective_from_dict(_objective_payload(metadata))
    ctx = MagicMock()
    ctx.formatter.heading.side_effect = lambda _level, text: f"## {text}\n"
    catalog = MagicMock()
    with (
        patch(
            "opentide.documentation.objects.objective.render_relations_diagram",
            return_value="relations-diagram",
        ),
        patch(
            "opentide.documentation.objects.objective.sections.render_metadata",
            return_value="meta\n",
        ),
        patch(
            "opentide.documentation.objects.objective.sections.render_description",
            return_value="desc\n",
        ),
        patch(
            "opentide.documentation.objects.objective.sections.render_objective_meta",
            return_value="objective-meta\n",
        ),
        patch(
            "opentide.documentation.objects.objective.sections.render_signals",
            return_value="signals\n",
        ),
        patch(
            "opentide.documentation.objects.objective.sections.render_signal_mdr_coverage",
            return_value="signal-matrix\n",
        ),
    ):
        rendered = ObjectiveRenderer(ctx, catalog).render(objective)
    assert "Detect lateral movement" in rendered
    assert "objective-meta" in rendered
    assert "signal-matrix" in rendered
    assert "relations-diagram" in rendered


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
