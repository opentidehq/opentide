"""Rule loader behaviour."""

from __future__ import annotations

from typing import Any

import opentide.loading.rule_loader as rule_loader_module
from opentide.models.platform import RuleConfigurations
from opentide.models.rule import DetectionRule


def test_load_rule_compat_removed() -> None:
    assert not hasattr(rule_loader_module, "load_rule_compat")


def test_load_rule_from_dict_typed_configurations(metadata: dict[str, Any]) -> None:
    payload = {
        "name": "Rule",
        "metadata": metadata,
        "description": "desc",
        "configurations": {
            "sentinel": {
                "enabled": True,
                "name": "S",
                "schema": "platform::sentinel::1.0",
                "status": "STAGING",
                "query": "SecurityEvent | take 1",
                "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
                "alert": {"title": "T", "suppression": False},
            }
        },
    }
    rule = rule_loader_module.load_rule_from_dict(payload)
    assert isinstance(rule.configurations, RuleConfigurations)
    assert rule.configurations.sentinel is not None
    assert rule.configurations.sentinel.query.startswith("SecurityEvent")


def test_load_rule_from_dict_minimal(metadata: dict[str, Any]) -> None:
    payload: dict[str, Any] = {
        "name": "Rule",
        "metadata": metadata,
        "description": "desc",
        "status": "STAGING",
        "severity": "High",
        "techniques": [],
        "configurations": {
            "sentinel": {
                "enabled": True,
                "name": "S",
                "schema": "platform::sentinel::1.0",
                "status": "STAGING",
                "query": "SecurityEvent | take 1",
                "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
                "alert": {"title": "T", "suppression": False},
            },
        },
    }
    rule = rule_loader_module.load_rule_from_dict(payload)
    assert isinstance(rule, DetectionRule)
    assert rule.name == "Rule"
