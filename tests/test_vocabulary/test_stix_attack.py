"""Tests for STIX ATT&CK vocabulary parsing."""

from __future__ import annotations

import json
from pathlib import Path

from opentide.vocabulary import stix_attack


def test_mitre_external_id_extracts_attack_id() -> None:
    obj = {
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1059", "url": "https://example.com"}
        ]
    }
    assert stix_attack._mitre_external_id(obj) == "T1059"


def test_build_tactic_name_map() -> None:
    objects = [
        {
            "type": "x-mitre-tactic",
            "x_mitre_shortname": "execution",
            "name": "Execution",
        }
    ]
    mapping = stix_attack.build_tactic_name_map(objects)
    assert mapping["execution"] == "Execution"


def test_load_stix_bundle_from_file(tmp_path: Path) -> None:
    bundle = {
        "type": "bundle",
        "objects": [{"type": "attack-pattern", "name": "Test Technique"}],
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    objects = stix_attack.load_stix_bundle(path)
    assert len(objects) == 1


def test_parse_techniques_extracts_entries() -> None:
    objects = [
        {
            "type": "x-mitre-tactic",
            "x_mitre_shortname": "execution",
            "name": "Execution",
        },
        {
            "type": "attack-pattern",
            "name": "Command and Scripting Interpreter",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "url": "https://example.com",
                }
            ],
            "kill_chain_phases": [{"phase_name": "execution"}],
        },
    ]
    entries = stix_attack.parse_techniques(objects)
    assert entries
    assert entries[0]["id"] == "T1059"
    assert entries[0]["link"] == "https://example.com"


def test_parse_groups_extracts_intrusion_sets() -> None:
    objects = [
        {
            "type": "intrusion-set",
            "name": "APT29",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}],
            "aliases": ["Cozy Bear"],
        }
    ]
    entries = stix_attack.parse_groups(objects)
    assert entries[0]["id"] == "G0016"
    assert entries[0]["alias"] == ["Cozy Bear"]


def test_parse_mitigations_extracts_course_of_action() -> None:
    objects = [
        {
            "type": "course-of-action",
            "name": "User Training",
            "external_references": [{"source_name": "mitre-attack", "external_id": "M1017"}],
        }
    ]
    entries = stix_attack.parse_mitigations(objects)
    assert entries[0]["id"] == "M1017"


def test_parse_datasources_and_components() -> None:
    objects = [
        {
            "type": "x-mitre-data-source",
            "id": "ds-1",
            "name": "Process",
            "external_references": [{"source_name": "mitre-attack", "external_id": "DS0009"}],
        },
        {
            "type": "x-mitre-data-component",
            "name": "Process Creation",
            "x_mitre_data_source_ref": "ds-1",
        },
    ]
    entries = stix_attack.parse_datasources(objects)
    assert len(entries) >= 2


def test_merge_technique_bundles(tmp_path: Path) -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Technique",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
            }
        ],
    }
    path = tmp_path / "enterprise.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    merged = stix_attack.merge_technique_bundles([(path, "ENT")])
    assert merged[0]["id"] == "T1059"
    assert merged[0]["name"].startswith("ENT")
