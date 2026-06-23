"""Objective and signal loaders."""

from __future__ import annotations

from typing import Any

from opentide.loading.objective_loader import load_objective_from_dict, load_signal_from_dict
from opentide.models.objective import DetectionObjective, DetectionSignal


def _objective_metadata() -> dict[str, Any]:
    return {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "schema": "objective::1.0",
        "version": 1,
        "created": "2026-01-01",
        "modified": "2026-01-02",
        "tlp": "clear",
    }


def _signal_payload() -> dict[str, Any]:
    return {
        "name": "Signal",
        "uuid": "00000000-0000-4000-8000-000000000099",
        "description": "sig",
        "severity": "Medium",
        "methodology": "analytics",
        "entities": ["host"],
        "data": {"availability": "Complete", "requirements": "logs"},
    }


def _objective_payload() -> dict[str, Any]:
    return {
        "name": "Objective",
        "metadata": _objective_metadata(),
        "composition": {"strategy": "synergetic", "description": "compose"},
        "objective": {
            "priority": "High",
            "type": "Threat",
            "description": "obj",
            "composition": {"strategy": "synergetic", "description": "compose"},
            "signals": [_signal_payload()],
        },
    }


def test_load_signal_from_dict_typed() -> None:
    signal = load_signal_from_dict(_signal_payload())
    assert isinstance(signal, DetectionSignal)
    assert signal.data.availability == "Complete"


def test_load_objective_from_dict_typed() -> None:
    objective = load_objective_from_dict(_objective_payload())
    assert isinstance(objective, DetectionObjective)
    assert len(objective.objective.signals) == 1
