"""opentide registry singleton behaviour."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from opentide import Opentide
from opentide.core import index_manager as index_mod
from opentide.core.registry import OpentideRegistry
from opentide.models.rule import DetectionRule


def test_opentide_singleton_type() -> None:
    assert isinstance(Opentide, OpentideRegistry)


def test_opentide_initialise_and_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    Opentide._initialised = False
    Opentide._index = None
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
    Opentide.initialise()
    assert Opentide._initialised is True
    assert Opentide.Rules == {}


def test_opentide_lookup_returns_none_for_missing() -> None:
    Opentide._initialised = False
    Opentide._rules = {}
    Opentide._threats = {}
    Opentide._objectives = {}
    Opentide._index = {"objects": {"rule": {}, "threat": {}, "objective": {}}, "configurations": {}}
    Opentide._initialised = True
    assert Opentide.lookup("missing-uuid") is None


def test_opentide_configuration_schema_sharing(monkeypatch: pytest.MonkeyPatch) -> None:
    Opentide._index = {
        "configurations": {
            "schema": {"templates": {"rule::description": "Describe the rule."}},
            "sharing": {"enabled": True},
            "global": {"objects": [], "metaschemas": {}, "templates": {}, "indexes": {}},
            "systems": {},
            "documentation": {},
            "deployment": {"statuses": {}},
            "visibility": {},
        },
        "objects": {"rule": {}, "threat": {}, "objective": {}},
    }
    Opentide._initialised = True
    assert Opentide.Configuration.Schema["templates"] == {"rule::description": "Describe the rule."}
    assert Opentide.Configuration.Sharing["enabled"] is True


def test_opentide_debug_ci_root_properties() -> None:
    assert isinstance(Opentide.debug, bool)
    assert isinstance(Opentide.ci, bool)
    assert isinstance(Opentide.root, Path)


def test_import_opentide_open_tide() -> None:
    from opentide import Opentide as OT

    assert OT is Opentide


def test_detection_rule_validate_query_no_validator(rule_payload: dict[str, Any]) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    registry = MagicMock()
    registry.Platforms = {"crowdstrike": MagicMock(validator=None)}
    bound = rule.bind_registry(registry)
    result = bound.validate_query("crowdstrike")
    assert result.ok is False
    assert "does not support query validation" in result.errors[0]


def test_models_accessor_schema_keys() -> None:
    Opentide._index = {
        "objects": {
            "rule": {"r1": {"name": "Rule"}},
            "objective": {"o1": {"name": "Objective"}},
            "threat": {"t1": {"name": "Threat"}},
            "signal": {"s1": {"name": "Signal"}},
        },
        "files": {},
        "configurations": {},
    }
    Opentide._rules = {}
    Opentide._threats = {}
    Opentide._objectives = {}
    Opentide._initialised = True
    models = Opentide.Models
    assert models.rules["r1"]["name"] == "Rule"
    assert models.objectives["o1"]["name"] == "Objective"
    assert models.threats["t1"]["name"] == "Threat"
    assert models.signals["s1"]["name"] == "Signal"
    flat = models.FlatIndex
    assert set(flat) == {"r1", "o1", "t1", "s1"}
    # Memoisation test: second access returns identical cached object
    assert Opentide.Models.FlatIndex is flat


def test_flat_index_not_stale_after_cache_drop() -> None:
    """A cache drop, not reload(), must not serve the previous object map."""
    Opentide._rules = {}
    Opentide._threats = {}
    Opentide._objectives = {}
    Opentide._initialised = True
    Opentide._index = {
        "objects": {
            "rule": {"old-rule": {"name": "Old"}},
            "objective": {},
            "threat": {},
            "signal": {},
        },
        "files": {},
        "configurations": {},
    }
    index_mod.IndexManager._cache = Opentide._index
    assert Opentide.Models.FlatIndex["old-rule"]["name"] == "Old"

    # Same drop the CLI and corpus helpers use. This is not IndexManager.reload().
    Opentide._index = None
    index_mod.IndexManager._cache = None
    assert index_mod.IndexManager._flat_cache is None
    assert index_mod.IndexManager._flat_cache_index is None

    Opentide._index = {
        "objects": {
            "rule": {"new-rule": {"name": "New"}},
            "objective": {},
            "threat": {},
            "signal": {},
        },
        "files": {},
        "configurations": {},
    }
    index_mod.IndexManager._cache = Opentide._index
    flat = Opentide.Models.FlatIndex
    assert set(flat) == {"new-rule"}
    assert flat["new-rule"]["name"] == "New"


def test_configuration_visibility_properties() -> None:
    Opentide._index = {
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
    Opentide._initialised = True
    visibility = Opentide.Configuration.Visibility
    assert visibility.assets is not None
    assert visibility.logsources is not None
    assert visibility.detectors is not None
    assert visibility.visibility is not None
    assert visibility.assets[0].name == "server"


def test_models_rules_lazy_load(rule_payload: dict[str, Any]) -> None:
    uuid = rule_payload["metadata"]["uuid"]
    Opentide._index = {
        "objects": {"rule": {uuid: rule_payload}, "threat": {}, "objective": {}},
        "files": {},
        "paths": {},
        "configurations": {},
    }
    Opentide._rules = {}
    Opentide._threats = {}
    Opentide._objectives = {}
    Opentide._initialised = True
    rules = Opentide.Models.Rules
    assert uuid in rules
    assert rules[uuid].name == "Test rule"


def test_configuration_deployment_statuses() -> None:
    Opentide._index = {
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
    Opentide._initialised = True
    statuses = Opentide.Configuration.Deployment.statuses
    assert statuses[0].name == "production"


def test_opentide_reload_refreshes_index(monkeypatch: pytest.MonkeyPatch) -> None:
    Opentide._initialised = True
    Opentide._rules = {"old": MagicMock()}
    sample_index = {
        "objects": {"rule": {}, "threat": {}, "objective": {}},
        "files": {},
        "configurations": {"global": {"objects": []}, "systems": {}},
    }
    monkeypatch.setattr(index_mod.IndexManager, "reload", lambda: None)
    monkeypatch.setattr(index_mod.IndexManager, "load", lambda: sample_index)
    Opentide.reload()
    assert Opentide._initialised is True
    assert Opentide._rules == {}
    assert Opentide._objects_loaded is False


def test_opentide_lookup_finds_typed_objects(rule_payload: dict[str, Any]) -> None:
    uuid = rule_payload["metadata"]["uuid"]
    rule = DetectionRule.from_yaml_dict(rule_payload)
    Opentide._rules = {uuid: rule}
    Opentide._threats = {}
    Opentide._objectives = {}
    Opentide._objects_loaded = True
    Opentide._initialised = True
    assert Opentide.lookup(uuid) is rule
    assert Opentide.lookup("nonexistent") is None


def test_models_chaining_property() -> None:
    threat_uuid = "00000000-0000-4000-8000-000000000060"
    Opentide._index = {
        "objects": {
            "threat": {
                threat_uuid: {
                    "name": "Chained Threat",
                    "threat": {
                        "chaining": [{"relation": "follows", "vector": "other-uuid"}],
                    },
                }
            },
            "rule": {},
            "objective": {},
            "signal": {},
        },
        "files": {},
        "configurations": {},
    }
    Opentide._initialised = True
    chains = Opentide.Models.chaining
    assert isinstance(chains, dict)


def test_configuration_documentation_properties() -> None:
    Opentide._index = {
        "configurations": {
            "documentation": {
                "flavor": "sentinel",
                "output": "analytics",
                "folder_index_pages": False,
                "object_names": {"rule": "Detection Rules"},
            }
        },
        "objects": {"rule": {}, "threat": {}, "objective": {}},
    }
    Opentide._initialised = True
    doc = Opentide.Configuration.Documentation
    assert doc.flavor == "sentinel"
    assert doc.output == "analytics"
    assert doc.folder_index_pages is False
    assert doc.object_names["rule"] == "Detection Rules"


def test_global_config_paths_and_exports() -> None:
    Opentide._index = {
        "configurations": {
            "global": {
                "objects": ["rule"],
                "exports": {"table": "table.csv"},
                "metaschemas": {"rule": "rule.yaml"},
            }
        },
        "objects": {"rule": {}, "threat": {}, "objective": {}},
        "paths": {"rule": "/tmp/rules"},
    }
    Opentide._initialised = True
    global_cfg = Opentide.Configuration.Global
    assert global_cfg.objects == ["rule"]
    assert global_cfg.exports.table == "table.csv"
    assert global_cfg.metaschemas["rule"] == "rule.yaml"


def test_legacy_export_getattr() -> None:
    from opentide.core import registry as reg_mod

    loader = reg_mod.__getattr__("ObjectLoader")
    assert loader is not None


def test_legacy_export_unknown_raises() -> None:
    from opentide.core import registry as reg_mod

    with pytest.raises(AttributeError):
        reg_mod.__getattr__("NotARealExport")
