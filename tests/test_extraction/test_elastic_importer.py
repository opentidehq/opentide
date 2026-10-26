"""Elastic importer: classification of imported rules."""

from __future__ import annotations

from opentide.extraction.elastic_importer import kibana_to_opentide


def test_imported_rules_are_not_marked_tlp_clear() -> None:
    """Every imported Elastic rule was stamped ``tlp: clear``.

    An enabled rule imports as PRODUCTION, which ``share push`` shares by
    default, so an organisation's private detections were published to MISP
    as TLP:CLEAR. Imports are now ``amber``, as the Sentinel importer's are.
    """
    rule = {
        "rule_id": "6b2e9c14-7a31-4f58-9d0c-1e8a4b7c2d90",
        "name": "Suspicious PowerShell",
        "description": "Detects suspicious PowerShell execution.",
        "type": "query",
        "language": "kuery",
        "query": 'process.name : "powershell.exe"',
        "index": ["logs-*"],
        "severity": "high",
        "enabled": True,
        "author": ["Elastic"],
        "created_at": "2026-09-29T10:00:00.000Z",
        "updated_at": "2026-09-29T12:00:00.000Z",
    }

    document = kibana_to_opentide(rule)

    assert document["metadata"]["tlp"] == "amber"
