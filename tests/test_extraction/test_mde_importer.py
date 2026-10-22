"""Defender for Endpoint importer: rendering one custom detection to rule YAML."""

from __future__ import annotations

from typing import Any

import yaml

from opentide.extraction import mde_importer


def _graph_rule(detector_id: str, name: str = "Suspicious logon") -> dict[str, Any]:
    return {
        "id": "123",
        "detectorId": detector_id,
        "displayName": name,
        "createdDateTime": "2026-01-01T00:00:00Z",
        "lastModifiedDateTime": "2026-01-02T00:00:00Z",
        "createdBy": "alice@example.com",
        "lastModifiedBy": "alice@example.com",
        "isEnabled": True,
        "schedule": {"period": "1H"},
        "queryCondition": {"queryText": "DeviceLogonEvents\n| take 1"},
        "detectionAction": {
            "alertTemplate": {
                "severity": "high",
                "description": "desc",
                "category": "InitialAccess",
                "impactedAssets": [],
            }
        },
    }


def test_render_rule_targets_the_tenant_it_was_listed_from() -> None:
    """Every imported rule used to name the original author's tenant, ``PandoraStores``."""
    rule = _graph_rule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name='Logon by "admin"')

    _filename, body = mde_importer._render_rule(rule, "Contoso")

    document = yaml.safe_load(body)
    assert document["name"] == 'Logon by "admin"'
    assert document["metadata"]["uuid"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert document["configurations"]["defender_for_endpoint"]["tenants"] == ["Contoso"]
    assert "PandoraStores" not in body
