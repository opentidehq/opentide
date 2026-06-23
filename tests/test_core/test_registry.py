"""OpenTide registry singleton behaviour."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from opentide import OpenTide
from opentide.core import index_manager as index_mod
from opentide.core.registry import OpenTideRegistry
from opentide.models.rule import DetectionRule


def test_opentide_singleton_type() -> None:
    assert isinstance(OpenTide, OpenTideRegistry)


def test_opentide_initialise_and_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    OpenTide._initialised = False
    OpenTide._index = None
    index_mod.IndexManager._cache = None

    sample_index = {
        "objects": {"rule": {}, "threat": {}, "objective": {}},
        "files": {},
        "configurations": {"global": {"objects": []}, "systems": {}},
        "paths": {},
        "vocabs": {},
        "metaschemas": {},
        "subschemas": {},
        "definitions": {},
        "templates": {},
        "json_schemas": {},
    }
    monkeypatch.setattr(index_mod.IndexManager, "load", lambda: sample_index)
    OpenTide.initialise()
    assert OpenTide._initialised is True
    assert OpenTide.Rules == {}


def test_opentide_lookup_returns_none_for_missing() -> None:
    OpenTide._initialised = False
    OpenTide._rules = {}
    OpenTide._threats = {}
    OpenTide._objectives = {}
    OpenTide._index = {"objects": {"rule": {}, "threat": {}, "objective": {}}, "configurations": {}}
    OpenTide._initialised = True
    assert OpenTide.lookup("missing-uuid") is None


def test_opentide_configuration_schema_sharing(monkeypatch: pytest.MonkeyPatch) -> None:
    OpenTide._index = {
        "configurations": {
            "schema": {"version": "1"},
            "sharing": {"enabled": True},
            "global": {"objects": [], "metaschemas": {}, "templates": {}, "indexes": {}},
            "systems": {},
            "documentation": {},
            "deployment": {"statuses": {}},
            "visibility": {},
        },
        "objects": {"rule": {}, "threat": {}, "objective": {}},
    }
    OpenTide._initialised = True
    assert OpenTide.Configuration.Schema["version"] == "1"
    assert OpenTide.Configuration.Sharing["enabled"] is True


def test_opentide_debug_ci_root_properties() -> None:
    assert isinstance(OpenTide.debug, bool)
    assert isinstance(OpenTide.ci, bool)
    assert isinstance(OpenTide.root, Path)


def test_import_opentide_open_tide() -> None:
    from opentide import OpenTide as OT

    assert OT is OpenTide


def test_detection_rule_validate_query_no_validator(rule_payload: dict[str, Any]) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    registry = MagicMock()
    registry.Platforms = {"crowdstrike": MagicMock(validator=None)}
    bound = rule.bind_registry(registry)
    result = bound.validate_query("crowdstrike")
    assert result.ok is False
    assert "does not support query validation" in result.errors[0]


def test_models_accessor_schema_keys() -> None:
    OpenTide._index = {
        "objects": {
            "rule": {"r1": {"name": "Rule"}},
            "objective": {"o1": {"name": "Objective"}},
            "threat": {"t1": {"name": "Threat"}},
            "signal": {"s1": {"name": "Signal"}},
        },
        "files": {},
        "configurations": {},
    }
    OpenTide._rules = {}
    OpenTide._threats = {}
    OpenTide._objectives = {}
    OpenTide._initialised = True
    models = OpenTide.Models
    assert models.rules["r1"]["name"] == "Rule"
    assert models.objectives["o1"]["name"] == "Objective"
    assert models.threats["t1"]["name"] == "Threat"
    assert models.signals["s1"]["name"] == "Signal"
    flat = models.FlatIndex
    assert set(flat) == {"r1", "o1", "t1", "s1"}


def test_configuration_visibility_properties() -> None:
    OpenTide._index = {
        "configurations": {
            "visibility": {
                "assets": [{"name": "server", "description": "Host", "criticality": "high"}],
                "logsources": [
                    {
                        "name": "windows",
                        "description": "Windows events",
                        "system": "sentinel",
                    }
                ],
                "detectors": [
                    {"name": "edr", "description": "EDR alerts"},
                ],
            }
        },
        "objects": {"rule": {}, "threat": {}, "objective": {}},
    }
    OpenTide._initialised = True
    visibility = OpenTide.Configuration.Visibility
    assert visibility.assets is not None
    assert visibility.logsources is not None
    assert visibility.detectors is not None
    assert visibility.visibility is not None
    assert visibility.assets[0].name == "server"


def test_models_rules_lazy_load(rule_payload: dict[str, Any]) -> None:
    uuid = rule_payload["metadata"]["uuid"]
    OpenTide._index = {
        "objects": {"rule": {uuid: rule_payload}, "threat": {}, "objective": {}},
        "files": {},
        "paths": {},
        "configurations": {},
    }
    OpenTide._rules = {}
    OpenTide._threats = {}
    OpenTide._objectives = {}
    OpenTide._initialised = True
    rules = OpenTide.Models.Rules
    assert uuid in rules
    assert rules[uuid].name == "Test rule"


def test_configuration_deployment_statuses() -> None:
    OpenTide._index = {
        "configurations": {
            "deployment": {
                "statuses": [
                    {
                        "name": "production",
                        "description": "Live",
                        "strategy": "RELEASE",
                    }
                ]
            }
        },
        "objects": {"rule": {}, "threat": {}, "objective": {}},
    }
    OpenTide._initialised = True
    statuses = OpenTide.Configuration.Deployment.statuses
    assert statuses[0].name == "production"
