"""Tests for MITRE ATT&CK threat mapping for Elastic Security (RFC 0007 §3)."""

from __future__ import annotations

from unittest.mock import MagicMock

from opentide.models.rule import DetectionRule
from opentide.platforms.elastic.attack import TACTIC_ORDER, resolve_elastic_threat


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
