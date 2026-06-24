"""Tests for PreflightGraph validation graph."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from opentide.generation.vocabulary import VocabularyDefinition, VocabularyEntry, VocabularyMetadata
from opentide.validation.preflight import ObjectRef, PreflightGraph
from opentide.validation.vocab_resolver import RuntimeEnumResolver


def _sample_vocab_resolver() -> RuntimeEnumResolver:
    meta = VocabularyMetadata(name="Severity", field="severity", key="name")
    entries = {"High": VocabularyEntry(name="High", description="High severity")}
    vocab = VocabularyDefinition(metadata=meta, entries=entries)
    return RuntimeEnumResolver({"severity": vocab})


def _minimal_index() -> dict:
    threat_uuid = "00000000-0000-4000-8000-000000000010"
    return {
        "objects": {
            "threat": {
                threat_uuid: {
                    "name": "Sample Threat",
                    "metadata": {"uuid": threat_uuid, "tlp": "clear"},
                    "threat": {"att&ck": ["T1059"], "chaining": []},
                }
            },
            "objective": {},
            "rule": {},
            "signal": {},
        },
        "files": {threat_uuid: "sample-threat.yaml"},
        "paths": {"tide": {"threat": "/tmp/threats"}},
        "configurations": {
            "global": {"objects": ["threat", "objective", "rule"]},
            "documentation": {
                "icons": {},
                "object_names": {
                    "threat": "Threat Vector",
                    "objective": "Detection Objective",
                    "rule": "Detection Rule",
                },
            },
            "schema": {"vocabulary": {}},
        },
        "vocabs": {},
    }


def test_preflight_graph_build_resolves_objects() -> None:
    graph = PreflightGraph.build(_minimal_index())
    threat_uuid = "00000000-0000-4000-8000-000000000010"
    ref = graph.resolve(threat_uuid)
    assert ref is not None
    assert ref.name == "Sample Threat"
    assert ref.object_type == "threat"
    assert ref.file_path == Path("/tmp/threats/sample-threat.yaml")


def test_preflight_graph_enum_values_for_object_type() -> None:
    graph = PreflightGraph.build(_minimal_index())
    values = graph.enum_values("threat")
    assert "00000000-0000-4000-8000-000000000010" in values


def test_preflight_graph_suggest_ref_for_object_type() -> None:
    resolver = _sample_vocab_resolver()
    graph = PreflightGraph(
        objects_by_type={"rule": {"uuid-1": {"name": "Alpha Rule"}}},
        objects_by_uuid={
            "uuid-1": ObjectRef(uuid="uuid-1", name="Alpha Rule", object_type="rule"),
        },
        files_index={},
        chaining_graph={},
        enum_resolver=resolver,
    )
    with patch("difflib.get_close_matches", return_value=["Alpha Rule"]):
        suggestion = graph.suggest_ref("rule", "Alfa Rule")
    assert suggestion == "uuid-1"


def test_preflight_graph_format_invalid_ref_with_suggestion() -> None:
    graph = PreflightGraph(
        objects_by_type={"rule": {}},
        objects_by_uuid={
            "uuid-1": ObjectRef(uuid="uuid-1", name="Alpha Rule", object_type="rule"),
        },
        files_index={},
        chaining_graph={},
        enum_resolver=_sample_vocab_resolver(),
    )
    with patch("difflib.get_close_matches", return_value=["Alpha Rule"]):
        message = graph.format_invalid_ref("rule", "Alfa Rule")
    assert "Alpha Rule" in message
    assert "uuid-1" in message


def test_preflight_graph_format_invalid_ref_without_suggestion() -> None:
    graph = PreflightGraph(
        objects_by_type={},
        objects_by_uuid={},
        files_index={},
        chaining_graph={},
        enum_resolver=_sample_vocab_resolver(),
    )
    message = graph.format_invalid_ref("severity", "ZZZZZ")
    assert "Unknown severity reference" in message


def test_preflight_graph_chaining_neighbors() -> None:
    graph = PreflightGraph(
        objects_by_type={},
        objects_by_uuid={},
        files_index={},
        chaining_graph={"tvm-1": {"follows": ["tvm-2"]}},
        enum_resolver=_sample_vocab_resolver(),
    )
    assert graph.chaining_neighbors("tvm-1") == {"follows": ["tvm-2"]}


def test_preflight_graph_parent_uuids() -> None:
    child_uuid = "00000000-0000-4000-8000-000000000020"
    parent_uuid = "00000000-0000-4000-8000-000000000021"
    graph = PreflightGraph(
        objects_by_type={"rule": {child_uuid: {"detection_model": parent_uuid}}},
        objects_by_uuid={
            child_uuid: ObjectRef(
                uuid=child_uuid,
                object_type="rule",
                name="Child Rule",
                file_path=Path("child.yaml"),
            )
        },
        files_index={},
        chaining_graph={},
        enum_resolver=_sample_vocab_resolver(),
    )
    assert graph.parent_uuids(child_uuid) == [parent_uuid]
