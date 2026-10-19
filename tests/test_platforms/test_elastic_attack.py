"""Tests for MITRE ATT&CK threat mapping for Elastic Security (RFC 0007 §3)."""

from __future__ import annotations

from unittest.mock import MagicMock

from opentide.models.rule import DetectionRule
from opentide.platforms.elastic.attack import (
    NON_ENTERPRISE_PREFIXES,
    TACTIC_MAP,
    TACTIC_ORDER,
    resolve_elastic_threat,
)


def _mock_rule(techniques: list[str], uuid: str = "test-uuid") -> DetectionRule:
    rule = MagicMock(spec=DetectionRule)
    rule.techniques = techniques
    rule.metadata = MagicMock()
    rule.metadata.uuid = uuid
    rule.configurations = None
    return rule


def test_tactics_in_rfc_table_order() -> None:
    # Multiple techniques across different tactics
    rule = _mock_rule(["T1105", "T1059", "T1071"])  # C2, Execution, C2
    threats = resolve_elastic_threat(rule)

    tactic_indices = [
        next(i for i, (stage, _) in enumerate(TACTIC_ORDER) if stage == t["tactic"]["name"])
        for t in threats
    ]
    assert tactic_indices == sorted(tactic_indices)


def test_techniques_sorted_by_id_and_subtechniques_nested() -> None:
    rule = _mock_rule(["T1059.001", "T1059.003", "T1059"])
    threats = resolve_elastic_threat(rule)
    assert len(threats) >= 1
    exec_tactic = next(t for t in threats if t["tactic"]["id"] == "TA0002")
    parent_tech = next(t for t in exec_tactic["technique"] if t["id"] == "T1059")
    assert "subtechnique" in parent_tech
    subs = parent_tech["subtechnique"]
    sub_ids = [s["id"] for s in subs]
    assert sub_ids == sorted(sub_ids)
    assert "T1059.001" in sub_ids
    assert "T1059.003" in sub_ids


def test_non_enterprise_techniques_skipped() -> None:
    # T0807 is ICS (Industrial), should be skipped
    rule = _mock_rule(["T0807", "T1105"])
    threats = resolve_elastic_threat(rule)
    assert not any(any(tech["id"] == "T0807" for tech in t["technique"]) for t in threats)
    assert any(any(tech["id"] == "T1105" for tech in t["technique"]) for t in threats)


def _tactic(threats: list[dict], tactic_id: str) -> dict:
    return next(t for t in threats if t["tactic"]["id"] == tactic_id)


def test_defense_impairment_technique_maps_to_ta0112() -> None:
    """T1685 is ATT&CK v19 Defense Impairment (#568)."""
    threats = resolve_elastic_threat(_mock_rule(["T1685", "T1685.002"]))

    assert [t["tactic"]["id"] for t in threats] == ["TA0112"]
    tactic = _tactic(threats, "TA0112")
    assert tactic["tactic"]["name"] == "Defense Impairment"
    assert tactic["tactic"]["reference"] == "https://attack.mitre.org/tactics/TA0112/"
    (technique,) = tactic["technique"]
    assert technique["id"] == "T1685"
    assert technique["name"] == "Disable or Modify Tools"
    assert technique["subtechnique"] == [
        {
            "id": "T1685.002",
            "name": "Disable or Modify Cloud Log",
            "reference": "https://attack.mitre.org/techniques/T1685/002",
        }
    ]


def test_stealth_technique_maps_to_ta0005() -> None:
    """ATT&CK v19 renamed Defense Evasion (TA0005) to Stealth."""
    threats = resolve_elastic_threat(_mock_rule(["T1027"]))

    assert [t["tactic"]["id"] for t in threats] == ["TA0005"]
    assert _tactic(threats, "TA0005")["tactic"]["name"] == "Stealth"


def test_revoked_defense_evasion_key_maps_to_stealth() -> None:
    """T1562.* is removed at att&ck::2.0 but still valid under 1.x with its old stage."""
    threats = resolve_elastic_threat(_mock_rule(["T1562.001"]))

    assert [t["tactic"]["id"] for t in threats] == ["TA0005"]
    tactic = _tactic(threats, "TA0005")
    assert tactic["tactic"]["name"] == "Stealth"
    (technique,) = tactic["technique"]
    assert technique["id"] == "T1562"
    assert [s["id"] for s in technique["subtechnique"]] == ["T1562.001"]
    assert technique["subtechnique"][0]["name"] == "Disable or Modify Tools"


def test_stealth_sorts_before_defense_impairment() -> None:
    threats = resolve_elastic_threat(_mock_rule(["T1685", "T1027", "T1059"]))

    assert [t["tactic"]["id"] for t in threats] == ["TA0002", "TA0005", "TA0112"]


def test_every_bundled_enterprise_stage_has_a_tactic() -> None:
    """A stage missing from TACTIC_MAP silently drops the tactic from every rule using it."""
    from opentide.generation.framework import VOCAB_INDEX

    entries = VOCAB_INDEX["att&ck"].entries
    stages = {
        stage.strip().lower()
        for entry in entries.values()
        if not str(entry.get("name", "")).startswith(NON_ENTERPRISE_PREFIXES)
        for stage in entry.get("tide.vocab.stages") or []
    }

    assert stages
    assert stages - set(TACTIC_MAP) == set()
