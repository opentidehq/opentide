"""Golden MISP envelopes from the sharing::misp::1.0 fixtures."""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path

import pytest

from opentide.sharing.document import TideDocument, load_document
from opentide.sharing.payload import build_event, distribution_for, tlp_allows

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sharing"


@pytest.mark.parametrize("name", ["rule", "objective", "threat"])
def test_golden_event_matches_the_spec_fixture(name: str) -> None:
    document = load_document((FIXTURES / f"{name}.yaml").read_text(encoding="utf-8"))
    built = build_event(document)
    expected = json.loads((FIXTURES / f"{name}-event.json").read_text(encoding="utf-8"))
    assert built.reason is None
    assert built.event == expected


def test_verbatim_object_is_the_file_text() -> None:
    text = (FIXTURES / "rule.yaml").read_text(encoding="utf-8")
    built = build_event(load_document(text))
    assert built.event is not None
    attributes = built.event["Event"]["Object"][0]["Attribute"]
    body = next(
        item["value"] for item in attributes if item["object_relation"] == "opentide-object"
    )
    assert body == text


def test_info_truncates_and_the_name_attribute_does_not() -> None:
    text = (FIXTURES / "rule.yaml").read_text(encoding="utf-8")
    long_name = "N" * 300
    text = text.replace("name: Sentinel KQL Rule", f"name: {long_name}", 1)
    built = build_event(load_document(text))
    assert built.event is not None
    assert built.event["Event"]["info"] == long_name[:255]
    attributes = built.event["Event"]["Object"][0]["Attribute"]
    assert attributes[0]["value"] == long_name


def test_distribution_follows_tlp() -> None:
    assert distribution_for("clear") == 1
    assert distribution_for("green") == 1
    assert distribution_for("amber") == 0
    assert distribution_for("amber+strict") == 0
    assert distribution_for("red") == 0
    assert tlp_allows("amber", "amber")
    assert not tlp_allows("red", "amber")


def test_pap_tag_and_unmapped_pap() -> None:
    text = (FIXTURES / "rule.yaml").read_text(encoding="utf-8")
    tagged = text.replace("tlp: clear\n", "tlp: amber\n  pap: white\n")
    built = build_event(load_document(tagged))
    assert built.event is not None
    assert [tag["name"] for tag in built.event["Event"]["Tag"]] == ["tlp:amber", "PAP:WHITE"]
    assert built.event["Event"]["distribution"] == 0
    unknown = text.replace("tlp: clear\n", "tlp: clear\n  pap: mauve\n")
    assert build_event(load_document(unknown)).reason == "unmapped_pap"


def test_rule_severity_matches_alert_severity_case_insensitively() -> None:
    text = (
        (FIXTURES / "rule.yaml")
        .read_text(encoding="utf-8")
        .replace("severity: High", "severity: low")
    )
    built = build_event(load_document(text))
    assert built.event is not None
    assert built.event["Event"]["threat_level_id"] == 3


def test_unquoted_created_date_and_version_without_leading_zeroes() -> None:
    text = (FIXTURES / "threat.yaml").read_text(encoding="utf-8")
    text = text.replace('created: "2026-01-01"', "created: 2026-01-01")
    text = text.replace("version: 1", "version: 01")
    document = load_document(text)
    assert document.metadata["created"] == date(2026, 1, 1)
    built = build_event(document)
    assert built.event is not None
    assert built.event["Event"]["date"] == "2026-01-01"
    version = next(
        item["value"]
        for item in built.event["Event"]["Object"][0]["Attribute"]
        if item["object_relation"] == "version"
    )
    assert version == "1"


def test_objective_relations_are_distinct_and_sorted() -> None:
    text = (FIXTURES / "objective.yaml").read_text(encoding="utf-8")
    extra = "    - 00000000-0000-4000-8001-000000000002\n"
    text = text.replace(
        "    - 00000000-0000-4000-8001-000000000001\n",
        "    - 00000000-0000-4000-8001-000000000001\n"
        "    - 00000000-0000-4000-8001-000000000001\n" + extra,
    )
    built = build_event(load_document(text))
    assert built.relations == (
        "00000000-0000-4000-8001-000000000001",
        "00000000-0000-4000-8001-000000000002",
    )


def test_non_canonical_relation_fails_the_object() -> None:
    text = (FIXTURES / "rule.yaml").read_text(encoding="utf-8")
    text = text.replace(
        "detection_model: 00000000-0000-4000-8002-000000000001",
        "detection_model: NOT-A-UUID",
    )
    assert build_event(load_document(text)).reason == "relation_uuid"


def test_missing_name_and_created_name_the_field() -> None:
    text = (FIXTURES / "rule.yaml").read_text(encoding="utf-8")
    blank = text.replace("name: Sentinel KQL Rule", "name: '   '", 1)
    assert build_event(load_document(blank)).reason == "name"
    undated = text.replace('created: "2026-01-01"', "created: yesterday")
    assert build_event(load_document(undated)).reason == "metadata.created"


def test_unknown_tlp_names_are_not_allowed() -> None:
    assert not tlp_allows("mauve", "amber")
    assert not tlp_allows("clear", "mauve")


def test_field_errors_name_the_blocking_field() -> None:
    text = (FIXTURES / "rule.yaml").read_text(encoding="utf-8")
    broken = TideDocument(text, {}, parse_error="yaml")
    assert build_event(broken).reason == "invalid_document"
    no_uuid = text.replace("  uuid: 00000000-0000-4000-8003-000000000001\n", "")
    assert build_event(load_document(no_uuid)).reason == "metadata.uuid"
    no_schema = text.replace("  schema: rule::1.0\n", "")
    assert build_event(load_document(no_schema)).reason == "invalid_document"
    no_version = text.replace("  version: 1\n", "")
    assert build_event(load_document(no_version)).reason == "metadata.version"
    bad_tlp = text.replace("tlp: clear", "tlp: mauve")
    assert build_event(load_document(bad_tlp)).reason == "unmapped_tlp"


def test_version_rejects_bools_floats_and_negatives() -> None:
    text = (FIXTURES / "rule.yaml").read_text(encoding="utf-8")
    for replacement, expected in (
        ("version: 1", "version: true"),
        ("version: 1", "version: 1.5"),
        ("version: 1", "version: -1"),
        ("version: 1", "version: nope"),
    ):
        built = build_event(load_document(text.replace(replacement, expected, 1)))
        assert built.reason == "metadata.version"
    quoted = build_event(load_document(text.replace("version: 1", 'version: "02"', 1)))
    assert quoted.event is not None


def test_created_accepts_a_datetime_and_rejects_other_types() -> None:
    text = (FIXTURES / "threat.yaml").read_text(encoding="utf-8")
    dated = text.replace('created: "2026-01-01"', "created: 2026-01-01 11:00:00")
    document = load_document(dated)
    assert isinstance(document.metadata["created"], datetime)
    built = build_event(document)
    assert built.event is not None
    assert built.event["Event"]["date"] == "2026-01-01"
    numeric = text.replace('created: "2026-01-01"', "created: 20260101")
    assert build_event(load_document(numeric)).reason == "metadata.created"
    short = text.replace('created: "2026-01-01"', 'created: "2026"')
    assert build_event(load_document(short)).reason == "metadata.created"
    invalid = text.replace('created: "2026-01-01"', 'created: "not-a-date"')
    assert build_event(load_document(invalid)).reason == "metadata.created"


def test_pap_must_be_a_mapped_string() -> None:
    text = (FIXTURES / "rule.yaml").read_text(encoding="utf-8")
    numbered = text.replace("tlp: clear\n", "tlp: clear\n  pap: 1\n")
    assert build_event(load_document(numbered)).reason == "unmapped_pap"


def test_optional_relations_and_rejected_relation_lists() -> None:
    rule = (FIXTURES / "rule.yaml").read_text(encoding="utf-8")
    omitted = rule.replace(
        "detection_model: 00000000-0000-4000-8002-000000000001\n",
        "",
    )
    assert build_event(load_document(omitted)).relations == ()
    objective = (FIXTURES / "objective.yaml").read_text(encoding="utf-8")
    empty = objective.replace(
        "  threats:\n    - 00000000-0000-4000-8001-000000000001\n",
        "  threats:\n",
    )
    assert build_event(load_document(empty)).relations == ()
    blank = objective.replace(
        "    - 00000000-0000-4000-8001-000000000001\n",
        "    - ''\n    - 00000000-0000-4000-8001-000000000001\n",
    )
    built = build_event(load_document(blank))
    assert built.relations == ("00000000-0000-4000-8001-000000000001",)
    scalar = objective.replace(
        "  threats:\n    - 00000000-0000-4000-8001-000000000001\n",
        "  threats: nope\n",
    )
    assert build_event(load_document(scalar)).reason == "relation_uuid"
    numbered = objective.replace(
        "    - 00000000-0000-4000-8001-000000000001\n",
        "    - 1\n",
    )
    assert build_event(load_document(numbered)).reason == "relation_uuid"


def test_unmatched_levels_are_undefined() -> None:
    rule = (
        (FIXTURES / "rule.yaml")
        .read_text(encoding="utf-8")
        .replace("severity: High", "severity: 1")
    )
    built = build_event(load_document(rule))
    assert built.event is not None
    assert built.event["Event"]["threat_level_id"] == 4
    threat = (FIXTURES / "threat.yaml").read_text(encoding="utf-8")
    threat = threat.replace("criticality: High", "criticality: high")
    folded = build_event(load_document(threat))
    assert folded.event is not None
    assert folded.event["Event"]["threat_level_id"] == 1
    unknown = threat.replace("criticality: high", "criticality: mythical")
    unmatched = build_event(load_document(unknown))
    assert unmatched.event is not None
    assert unmatched.event["Event"]["threat_level_id"] == 4


def test_duplicate_cluster_tags_are_not_repeated() -> None:
    document = load_document((FIXTURES / "rule.yaml").read_text(encoding="utf-8"))
    built = build_event(document, ("tlp:clear", 'misp-galaxy:mitre-attack-pattern="T1059"'))
    assert built.event is not None
    assert [tag["name"] for tag in built.event["Event"]["Tag"]] == [
        "tlp:clear",
        'misp-galaxy:mitre-attack-pattern="T1059"',
    ]


def test_cluster_sources_skip_blank_techniques_and_unstructured_actors() -> None:
    text = (FIXTURES / "threat.yaml").read_text(encoding="utf-8")
    text = text.replace("    - T1059\n", "    - T1059\n    - '  '\n    - T1059\n")
    text = text.replace(
        "    - name: att&ck::G0007\n",
        "    - 1\n    - name: ''\n    - name: att&ck::G0007\n",
    )
    built = build_event(load_document(text))
    assert built.cluster_sources.count("technique:T1059") == 1
    assert "actor:att&ck::G0007" in built.cluster_sources


def test_objective_attack_list_becomes_technique_sources() -> None:
    text = (FIXTURES / "objective.yaml").read_text(encoding="utf-8")
    text = text.replace(
        "  threats:\n",
        "  mitre_attack:\n    - T1110\n  threats:\n",
    )
    built = build_event(load_document(text))
    assert "technique:T1110" in built.cluster_sources


def test_vocab_entries_that_are_not_objects_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.sharing import payload

    def fake_loads(_text: str) -> dict[str, object]:
        return {"keys": ["skip", {"name": "clear", "misp": "tlp:clear"}, {"name": 1}]}

    monkeypatch.setattr(payload.tomllib, "loads", fake_loads)
    payload._VOCAB.clear()
    try:
        mapping = payload._vocab_misp("tlp.vocab.toml")
        assert mapping == {"clear": "tlp:clear"}
    finally:
        payload._VOCAB.clear()


def test_cluster_sources_include_techniques_and_scoped_actors() -> None:
    threat = load_document((FIXTURES / "threat.yaml").read_text(encoding="utf-8"))
    built = build_event(threat)
    assert "technique:T1059" in built.cluster_sources
    assert "actor:att&ck::G0007" in built.cluster_sources
    assert "actor:misp::5b4ee3ea-eee3-4c8e-8323-85ae32658754" in built.cluster_sources
    assert built.event is not None
    assert [tag["name"] for tag in built.event["Event"]["Tag"]] == ["tlp:clear"]
