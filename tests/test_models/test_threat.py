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
            "impact": ["Data Breach"],
            "leverage": ["High"],
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
            "impact": ["Data Breach"],
            "leverage": ["High"],
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


def test_threat_cve_field_roundtrip(metadata: dict[str, Any]) -> None:
    payload = _threat_payload(metadata, actors=None)
    payload["threat"]["cve"] = ["CVE-2024-3094", "GHSA-rxwq-x6h5-x525", "GCVE-0-2024-3094"]
    tvm = ThreatVector.from_yaml_dict(payload)
    assert tvm.threat.cve == ["CVE-2024-3094", "GHSA-rxwq-x6h5-x525", "GCVE-0-2024-3094"]


def test_threat_actors_reject_vocab_id_strings(metadata: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ThreatVector.from_yaml_dict(_threat_payload(metadata, actors=["G0006"]))


def _with(metadata: dict[str, Any], **threat: Any) -> dict[str, Any]:
    payload = _threat_payload(metadata, actors=None)
    payload["threat"].update(threat)
    return payload


def _errors(payload: dict[str, Any]) -> list[dict[str, Any]]:
    with pytest.raises(ValidationError) as excinfo:
        ThreatVector.from_yaml_dict(payload)
    return [
        {"loc": err["loc"], "type": err["type"], "msg": err["msg"]}
        for err in excinfo.value.errors()
    ]


def test_impact_and_leverage_keep_every_listed_name(metadata: dict[str, Any]) -> None:
    tvm = ThreatVector.from_yaml_dict(
        _with(
            metadata,
            impact=["Data Breach", "Identity Theft"],
            leverage=["Elevation of privilege", "Repudiation"],
        )
    )
    assert tvm.threat.impact == ["Data Breach", "Identity Theft"]
    assert tvm.threat.leverage == ["Elevation of privilege", "Repudiation"]


@pytest.mark.parametrize("field", ["impact", "leverage"])
def test_a_single_string_is_not_a_list(metadata: dict[str, Any], field: str) -> None:
    errors = _errors(_with(metadata, **{field: "Data Breach"}))
    assert errors == [
        {
            "loc": ("threat", field),
            "type": "vocab_list_type",
            "msg": f"must be a YAML list of {field} vocabulary names, not a single string",
        }
    ]


@pytest.mark.parametrize("field", ["impact", "leverage"])
def test_an_empty_list_is_rejected(metadata: dict[str, Any], field: str) -> None:
    errors = _errors(_with(metadata, **{field: []}))
    assert [(err["loc"], err["type"]) for err in errors] == [(("threat", field), "too_short")]


@pytest.mark.parametrize("field", ["impact", "leverage"])
def test_a_packed_string_is_rejected_not_split_or_truncated(
    metadata: dict[str, Any], field: str
) -> None:
    errors = _errors(_with(metadata, **{field: "Data Breach; Identity Theft"}))
    assert errors == [
        {
            "loc": ("threat", field),
            "type": "vocab_list_type",
            "msg": (
                f"must be a YAML list of {field} vocabulary names, not a single string; "
                "list each name in 'Data Breach; Identity Theft' as its own item"
            ),
        }
    ]


@pytest.mark.parametrize("field", ["impact", "leverage"])
def test_a_packed_list_item_is_rejected_at_its_index(metadata: dict[str, Any], field: str) -> None:
    packed = "Elevation of privilege; Repudiation"
    errors = _errors(_with(metadata, **{field: ["Data Breach", packed]}))
    assert errors == [
        {
            "loc": ("threat", field, 1),
            "type": "vocab_packed_names",
            "msg": (
                f"'{packed}' packs several vocabulary names into one string; "
                "list each name as its own item"
            ),
        }
    ]


def test_impact_and_leverage_are_non_empty_string_arrays_in_the_json_schema() -> None:
    body = ThreatVector.model_json_schema(by_alias=True)["$defs"]["ThreatBody"]["properties"]
    for field in ("impact", "leverage"):
        assert body[field]["type"] == "array"
        assert body[field]["items"] == {"type": "string"}
        assert body[field]["minItems"] == 1
        assert body[field]["tide.vocab"] is True
