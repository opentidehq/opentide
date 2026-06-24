"""Object vocabulary index building."""

from __future__ import annotations

from unittest.mock import patch

from opentide.indexing.object_vocab import build_object_vocabularies, run


def test_build_object_vocabularies_mdr() -> None:
    objects = {
        "rule": {
            "uuid-1": {
                "name": "Rule A",
                "metadata": {"tlp": "clear"},
                "description": "Detects X",
            }
        }
    }
    vocab = build_object_vocabularies(
        object_scope=["rule"],
        models_index=objects,
        icons={"rule": "icon"},
        object_names={"rule": "Detection Rules"},
    )
    assert "rule" in vocab
    assert "uuid-1" in vocab["rule"]["entries"]
    assert vocab["rule"]["entries"]["uuid-1"]["name"] == "Rule A"


def test_build_object_vocabularies_threat_and_objective() -> None:
    objects = {
        "threat": {
            "t1": {
                "name": "Threat A",
                "metadata": {"tlp": "amber"},
                "threat": {"description": "Threat desc"},
                "actor": {"aliases": ["APT1"]},
                "criticality": "high",
            }
        },
        "objective": {
            "o1": {
                "name": "Objective A",
                "metadata": {"tlp": "clear"},
                "objective": {
                    "description": "Obj desc",
                    "priority": "P1",
                    "signals": [
                        {
                            "uuid": "s1",
                            "name": "Signal",
                            "severity": "High",
                            "description": "Signal desc",
                        }
                    ],
                },
            }
        },
    }
    vocab = build_object_vocabularies(
        object_scope=["threat", "objective"],
        models_index=objects,
        icons={"threat": "t", "objective": "o"},
        object_names={"threat": "Threats", "objective": "Objectives"},
    )
    assert vocab["threat"]["entries"]["t1"]["aliases"] == ["APT1"]
    assert vocab["objective"]["entries"]["o1"]["criticality"] == "P1"
    assert "s1" in vocab["objective"]["entries"]
    assert vocab["objective"]["entries"]["s1"]["name"] == "Objective A::Signal"


def test_build_object_vocabularies_adds_empty_objective_when_missing() -> None:
    vocab = build_object_vocabularies(
        object_scope=["rule"],
        models_index={"rule": {}},
        icons={},
        object_names={"rule": "Rules", "objective": "Objectives"},
    )
    assert "objective" in vocab
    assert vocab["objective"]["entries"] == {}


def test_run_builds_from_index_manager() -> None:
    index = {
        "configurations": {
            "global": {"objects": ["rule"]},
            "documentation": {"icons": {"rule": "r"}, "object_names": {"rule": "Rules"}},
        },
        "objects": {
            "rule": {
                "u1": {
                    "name": "Rule",
                    "metadata": {"tlp": "clear"},
                    "description": "d",
                }
            }
        },
    }
    with patch("opentide.indexing.object_vocab.IndexManager.load", return_value=index):
        vocab = run()
    assert "rule" in vocab
    assert "u1" in vocab["rule"]["entries"]
