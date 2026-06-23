"""DetectionObjective model behaviour."""

from __future__ import annotations

from typing import Any

from opentide.models.objective import DetectionObjective


def test_detection_objective_from_yaml_dict(metadata: dict[str, Any]) -> None:
    payload = {
        "name": "Objective",
        "metadata": {**metadata, "schema": "objective::1.0"},
        "composition": {"strategy": "synergetic", "description": "compose"},
        "objective": {
            "priority": "High",
            "type": "Threat",
            "description": "obj",
            "composition": {"strategy": "synergetic", "description": "compose"},
            "signals": [
                {
                    "name": "Signal",
                    "uuid": "00000000-0000-4000-8000-000000000099",
                    "description": "sig",
                    "severity": "Medium",
                    "methodology": "analytics",
                    "entities": ["host"],
                    "data": {"availability": "Complete", "requirements": "logs"},
                }
            ],
        },
    }
    dom = DetectionObjective.from_yaml_dict(payload)
    assert DetectionObjective.schema_identifier() == "objective::1.0"
    assert len(dom.objective.signals) == 1
