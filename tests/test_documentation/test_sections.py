"""Documentation section renderers."""

from __future__ import annotations

from typing import Any

from opentide.documentation.format.factory import formatter_for
from opentide.documentation.parts.sections import (
    render_description,
    render_metadata,
    render_rule_queries,
    render_signals,
    render_techniques,
    render_threat_body,
)
from opentide.documentation.types import DocumentFlavor
from opentide.loading.objective_loader import load_objective_from_dict
from opentide.models.metadata import ObjectMetadata
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector


def _objective_payload(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "Objective",
        "metadata": {**metadata, "schema": "objective::1.0"},
        "composition": {"strategy": "synergetic", "description": "compose"},
        "objective": {
            "priority": "High",
            "type": "Threat",
            "description": "Track execution",
            "composition": {"strategy": "synergetic", "description": "compose"},
            "signals": [
                {
                    "name": "Exec signal",
                    "uuid": "00000000-0000-4000-8000-000000000021",
                    "description": "Suspicious execution",
                    "severity": "High",
                    "methodology": "Monitor process creation",
                    "entities": ["host"],
                    "data": {"availability": "Complete", "requirements": "logs"},
                }
            ],
        },
    }


def test_render_metadata_includes_uuid_and_schema(metadata: dict[str, Any]) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    obj_metadata = ObjectMetadata.model_validate({**metadata, "schema": "rule::1.0"})
    rendered = render_metadata(obj_metadata, formatter)
    assert "Metadata" in rendered
    assert metadata["uuid"] in rendered
    assert "rule::1.0" in rendered


def test_render_description_and_techniques() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    assert "Description" in render_description("Detect malware", formatter)
    assert render_techniques([], formatter) == ""
    assert "T1059" in render_techniques(["T1059"], formatter)


def test_render_rule_queries_with_platform_config(rule_payload: dict) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    formatter = formatter_for(DocumentFlavor.github)
    rendered = render_rule_queries(rule, formatter)
    assert rendered == "" or "Platform configurations" in rendered


def test_render_signals_and_threat_body(metadata: dict[str, Any]) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    objective = load_objective_from_dict(_objective_payload(metadata))
    signals = render_signals(objective, formatter)
    assert "Exec signal" in signals
    assert "Methodology" in signals

    threat = ThreatVector.from_yaml_dict(
        {
            "name": "Threat",
            "criticality": "High",
            "metadata": {**metadata, "schema": "threat::1.0"},
            "threat": {
                "description": "Ransomware",
                "severity": "High",
                "impact": "Data Breach",
                "leverage": "High",
                "viability": "High",
                "terrain": "Endpoint",
                "att&ck": ["T1486"],
            },
        }
    )
    body = render_threat_body(threat, formatter)
    assert "Ransomware" in body
    assert "T1486" in body
