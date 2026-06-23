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
        "objects": {"mdr": {}, "tvm": {}, "dom": {}},
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
    OpenTide._index = {"objects": {"mdr": {}, "tvm": {}, "dom": {}}, "configurations": {}}
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
        "objects": {"mdr": {}, "tvm": {}, "dom": {}},
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
