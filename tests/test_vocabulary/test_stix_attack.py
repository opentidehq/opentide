"""Tests for STIX ATT&CK vocabulary parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentide.vocabulary import stix_attack


def test_mitre_external_id_extracts_attack_id() -> None:
    obj = {
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1059", "url": "https://example.com"}
        ]
    }
    assert stix_attack._mitre_external_id(obj) == "T1059"


def test_mitre_external_id_returns_none_without_attack_reference() -> None:
    assert stix_attack._mitre_external_id({"external_references": []}) is None


def test_mitre_url_extracts_attack_link() -> None:
    obj = {
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1059", "url": "https://example.com"}
        ]
    }
    assert stix_attack._mitre_url(obj) == "https://example.com"


def test_load_stix_bundle_accepts_object_list(tmp_path: Path) -> None:
    path = tmp_path / "objects.json"
    path.write_text(json.dumps([{"type": "attack-pattern", "name": "Technique"}]), encoding="utf-8")
    assert len(stix_attack.load_stix_bundle(path)) == 1


def test_load_stix_bundle_accepts_objects_wrapper(tmp_path: Path) -> None:
    path = tmp_path / "wrapper.json"
    path.write_text(json.dumps({"objects": [{"type": "attack-pattern"}]}), encoding="utf-8")
    assert len(stix_attack.load_stix_bundle(path)) == 1


def test_load_stix_bundle_rejects_unknown_format(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"type": "not-a-bundle"}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unrecognised STIX bundle format"):
        stix_attack.load_stix_bundle(path)


def test_normalise_tactic_name_maps_ics_evasion() -> None:
    assert stix_attack._normalise_tactic_name("Evasion Ics") == "Defense Evasion"
    assert stix_attack._normalise_tactic_name("Discovery Ics") == "Discovery"


def test_parse_techniques_skips_deprecated_and_non_technique_ids() -> None:
    objects = [
        {
            "type": "attack-pattern",
            "name": "Deprecated",
            "x_mitre_deprecated": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
        },
        {
            "type": "attack-pattern",
            "name": "Revoked",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0002"}],
        },
        {
            "type": "attack-pattern",
            "name": "Wrong id",
            "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}],
        },
    ]
    assert stix_attack.parse_techniques(objects) == []


def test_parse_groups_honours_prefix_and_skips_revoked() -> None:
    objects = [
        {
            "type": "intrusion-set",
            "name": "Old",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}],
        },
        {
            "type": "intrusion-set",
            "name": "APT29",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}],
        },
    ]
    entries = stix_attack.parse_groups(objects, prefix="ENT")
    assert entries[0]["name"].startswith("[ENT]")


def test_parse_groups_includes_link_when_present() -> None:
    objects = [
        {
            "type": "intrusion-set",
            "name": "APT29",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "G0016",
                    "url": "https://attack.mitre.org/groups/G0016",
                }
            ],
        }
    ]
    entries = stix_attack.parse_groups(objects)
    assert entries[0]["link"] == "https://attack.mitre.org/groups/G0016"


def test_parse_groups_skips_non_group_ids() -> None:
    objects = [
        {
            "type": "intrusion-set",
            "name": "Not a group id",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
        }
    ]
    assert stix_attack.parse_groups(objects) == []


def test_parse_mitigations_includes_link_when_present() -> None:
    objects = [
        {
            "type": "course-of-action",
            "name": "Training",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "M1017",
                    "url": "https://attack.mitre.org/mitigations/M1017",
                }
            ],
        }
    ]
    entries = stix_attack.parse_mitigations(objects)
    assert entries[0]["link"].endswith("M1017")


def test_build_tactic_name_map() -> None:
    objects = [
        {
            "type": "x-mitre-tactic",
            "x_mitre_shortname": "execution",
            "name": "Execution",
        },
        {
            "type": "x-mitre-tactic",
            "x-mitre-shortname": "discovery",
            "name": "Discovery",
        },
    ]
    mapping = stix_attack.build_tactic_name_map(objects)
    assert mapping["execution"] == "Execution"
    assert mapping["discovery"] == "Discovery"


def test_parse_datasources_skips_sources_without_external_id() -> None:
    objects = [
        {
            "type": "x-mitre-data-source",
            "id": "ds-1",
            "name": "Process",
        }
    ]
    assert stix_attack.parse_datasources(objects) == []


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


def test_parse_mitigations_skips_deprecated_entries() -> None:
    objects = [
        {
            "type": "course-of-action",
            "name": "Old",
            "x_mitre_deprecated": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "M1000"}],
        }
    ]
    assert stix_attack.parse_mitigations(objects) == []


def test_parse_mitigations_skips_non_mitigation_ids() -> None:
    objects = [
        {
            "type": "course-of-action",
            "name": "Wrong prefix",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
        }
    ]
    assert stix_attack.parse_mitigations(objects) == []


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


def test_parse_datasources_includes_source_link() -> None:
    objects = [
        {
            "type": "x-mitre-data-source",
            "id": "ds-1",
            "name": "Process",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "DS0009",
                    "url": "https://attack.mitre.org/datasources/DS0009",
                }
            ],
        }
    ]
    entries = stix_attack.parse_datasources(objects)
    assert entries[0]["link"] == "https://attack.mitre.org/datasources/DS0009"


def test_parse_datasources_component_uses_parent_metadata() -> None:
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
    component = next(entry for entry in entries if entry["name"] == "Process Creation")
    assert component["id"] == "DS0009"


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
