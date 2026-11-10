"""DetectionObjective model behaviour."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from opentide._models.objective import DetectionObjective


def test_detection_objective_from_yaml_dict(metadata: dict[str, Any]) -> None:
    payload = {
        "name": "Objective",
        "metadata": {**metadata, "schema": "objective::1.0"},
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


def test_a_root_composition_is_an_unknown_key(metadata: dict[str, Any]) -> None:
    """The composition is `objective.composition`; a root one is refused, not dropped."""
    payload = {
        "name": "Objective",
        "metadata": {**metadata, "schema": "objective::1.0"},
        "composition": {"strategy": "synergetic", "description": "compose"},
        "objective": {
            "priority": "High",
            "type": "Threat",
            "description": "obj",
            "composition": {"strategy": "synergetic", "description": "compose"},
        },
    }
    with pytest.raises(ValidationError) as caught:
        DetectionObjective.from_yaml_dict(payload)
    assert ("composition",) in [error["loc"] for error in caught.value.errors()]
