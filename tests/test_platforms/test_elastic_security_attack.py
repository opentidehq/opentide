"""Unit tests for Elastic Security ATT&CK threat mapping."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.platforms.elastic_security.attack import (
    TACTIC_MAP,
    normalize_tactic,
    resolve_elastic_threat,
)


def test_normalize_tactic_typo_tolerance() -> None:
    tactic = normalize_tactic("Priviledge Escalation")
    assert tactic is not None
    assert tactic["id"] == "TA0004"
    assert tactic["name"] == "Privilege Escalation"

    tactic2 = normalize_tactic("Privilege Escalation")
    assert tactic2 is not None
    assert tactic2["id"] == "TA0004"

    tactic3 = normalize_tactic("Defense Evasion")
    assert tactic3 is not None
    assert tactic3["id"] == "TA0005"


def test_tactic_name_to_id_lookup() -> None:
    assert TACTIC_MAP["privilege escalation"]["id"] == "TA0004"
    assert TACTIC_MAP["defense evasion"]["id"] == "TA0005"
    assert TACTIC_MAP["execution"]["id"] == "TA0002"
    assert TACTIC_MAP["initial access"]["id"] == "TA0001"


def test_resolve_elastic_threat_explicit_override() -> None:
    explicit = [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0001", "name": "Initial Access", "reference": "https://..."},
            "technique": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        }
    ]
    mock_rule = MagicMock()
    mock_rule.metadata.uuid = "00000000-0000-4000-8003-000000000001"
    mock_rule.configurations.elastic_security.threat = explicit

    result = resolve_elastic_threat(mock_rule)
    assert result == explicit


def test_resolve_elastic_threat_subtechnique_nesting_and_inheritance() -> None:
    mock_rule = MagicMock()
    mock_rule.metadata.uuid = "00000000-0000-4000-8003-000000000001"
    mock_rule.configurations.elastic_security.threat = None

    # Suppose techniques_resolver returns an inherited technique T1548.002 and T1059.001
    with (
        patch("opentide.platforms.elastic_security.attack.get_type", return_value="rule"),
        patch(
            "opentide.platforms.elastic_security.attack.techniques_resolver",
            return_value=["T1548.002", "T1059.001"],
        ),
    ):
        result = resolve_elastic_threat(mock_rule)

    assert len(result) >= 1
    # Check that tactics have id, name, reference
    for threat in result:
        assert threat["framework"] == "MITRE ATT&CK"
        assert "id" in threat["tactic"]
        assert threat["tactic"]["id"].startswith("TA")
        assert "reference" in threat["tactic"]

    # Check that T1548.002 is nested under T1548
    priv_threat = next((t for t in result if t["tactic"]["id"] == "TA0004"), None)
    assert priv_threat is not None
    t1548 = next((tech for tech in priv_threat["technique"] if tech["id"] == "T1548"), None)
    assert t1548 is not None
    assert "subtechnique" in t1548
    sub = next((s for s in t1548["subtechnique"] if s["id"] == "T1548.002"), None)
    assert sub is not None
    assert sub["name"] == "Bypass User Account Control"
    assert sub["reference"] == "https://attack.mitre.org/techniques/T1548/002"


def test_resolve_elastic_threat_unindexed_uuid_uses_data_techniques_without_resolver() -> None:
    mock_rule = MagicMock()
    mock_rule.metadata.uuid = "non-existent-uuid-9999"
    mock_rule.configurations.elastic_security.threat = None
    mock_rule.techniques = ["T1548.002"]

    with patch("opentide.platforms.elastic_security.attack.techniques_resolver") as mock_resolver:
        result = resolve_elastic_threat(mock_rule)
        mock_resolver.assert_not_called()

    assert len(result) >= 1
    priv_threat = next((t for t in result if t["tactic"]["id"] == "TA0004"), None)
    assert priv_threat is not None
