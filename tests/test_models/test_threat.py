"""ThreatVector model behaviour."""

from __future__ import annotations

from typing import Any

from opentide.models.threat import ThreatVector


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
            "terrain": "Endpoint",
            "att&ck": ["T1059"],
        },
    }
    tvm = ThreatVector.from_yaml_dict(payload)
    assert ThreatVector.schema_identifier() == "threat::1.0"
    assert tvm.threat.att_ck == ["T1059"]
