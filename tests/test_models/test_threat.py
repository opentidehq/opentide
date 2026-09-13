"""ThreatVector model behaviour."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from opentide.models.threat import ThreatActor, ThreatVector


def test_threat_vector_from_yaml_dict(metadata: dict[str, Any]) -> None:
    payload = {
        "name": "TVM",
        "criticality": "High",
        "metadata": {**metadata, "schema": "threat::1.0"},
        "threat": {
            "description": "d",
            "severity": "High",
            "impact": "Data Breach",
            "leverage": "High",
            "viability": "High",
            "terrain": "Endpoint workstations and user devices.",
            "surface": ["Windows::Desktop"],
            "att&ck": ["T1059"],
        },
    }
    tvm = ThreatVector.from_yaml_dict(payload)
    assert ThreatVector.schema_identifier() == "threat::1.0"
    assert tvm.threat.att_ck == ["T1059"]


def _threat_payload(metadata: dict[str, Any], *, actors: Any) -> dict[str, Any]:
    return {
        "name": "TVM",
        "criticality": "High",
        "metadata": {**metadata, "schema": "threat::1.0"},
        "threat": {
            "description": "d",
            "severity": "High",
            "impact": "Data Breach",
            "leverage": "High",
            "viability": "High",
            "terrain": "Endpoint workstations and user devices.",
            "surface": ["Windows::Desktop"],
            "att&ck": ["T1059"],
            "actors": actors,
        },
    }


def test_threat_actors_are_objects(metadata: dict[str, Any]) -> None:
    tvm = ThreatVector.from_yaml_dict(
        _threat_payload(
            metadata,
            actors=[
                {
                    "name": "att&ck::G0006",
                    "sighting": "Simulated credential access.",
                    "references": ["https://attack.mitre.org/groups/G0006"],
                }
            ],
        )
    )
    assert tvm.threat.actors is not None
    actor = tvm.threat.actors[0]
    assert isinstance(actor, ThreatActor)
    assert actor.name == "att&ck::G0006"
    assert actor.sighting == "Simulated credential access."
    assert actor.references == ["https://attack.mitre.org/groups/G0006"]


def test_threat_actors_reject_vocab_id_strings(metadata: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ThreatVector.from_yaml_dict(_threat_payload(metadata, actors=["G0006"]))
