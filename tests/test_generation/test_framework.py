"""Tests for generation framework helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.generation import framework as fw


def test_unroll_dot_dict_single_key() -> None:
    result = fw.unroll_dot_dict({"a.b.c": "value"})
    assert result == {"a": {"b": {"c": "value"}}}


def test_unroll_dot_dict_multiple_keys_returns_none(capsys) -> None:
    result = fw.unroll_dot_dict({"a": 1, "b": 2})
    assert result is None


def test_key_value_transform() -> None:
    rows = [{"key": "host", "value": "server1"}, {"key": "port", "value": "443"}]
    assert fw.key_value_transform(rows) == {"host": "server1", "port": "443"}


def test_deep_update_nested() -> None:
    data = {"outer": {"inner": {"target": "old"}}}
    fw.deep_update(data, "target", "new")
    assert data["outer"]["inner"]["target"] == "new"


def test_strip_vocab_stage_prefix() -> None:
    vocab_index = MagicMock()
    vocab_index.metadata.get.return_value = [{"id": "OS"}]
    with patch.object(fw, "VOCAB_INDEX", {"surface": vocab_index}):
        assert fw.strip_vocab_stage_prefix("surface", "OS::Windows::Desktop") == "Windows::Desktop"
        assert fw.strip_vocab_stage_prefix("surface", "PlainValue") == "PlainValue"


def test_get_type_from_schema(rule_payload: dict) -> None:
    uuid = rule_payload["metadata"]["uuid"]
    with (
        patch.object(fw, "MODELS_INDEX", {"rule": {uuid: rule_payload}}),
        patch("opentide.generation.framework.OpenTide") as mock_ot,
    ):
        mock_ot.Models.FlatIndex.get.return_value = rule_payload
        assert fw.get_type(uuid) == "rule"


def test_get_type_mute_returns_none_for_missing() -> None:
    with patch("opentide.generation.framework.OpenTide") as mock_ot:
        mock_ot.Models.FlatIndex.get.return_value = {}
        assert fw.get_type("missing", mute=True) is None


def test_parents_for_objective(rule_payload: dict) -> None:
    objective_uuid = "00000000-0000-4000-8000-000000000030"
    threat_uuid = "00000000-0000-4000-8000-000000000031"
    objective = {
        "name": "Objective",
        "metadata": {"schema": "objective::1.0", "uuid": objective_uuid},
        "objective": {"threats": [threat_uuid]},
    }
    with (
        patch.object(fw, "MODELS_INDEX", {"objective": {objective_uuid: objective}}),
        patch("opentide.generation.framework.OpenTide") as mock_ot,
    ):
        mock_ot.Models.FlatIndex.get.return_value = objective
        assert fw.parents(objective_uuid) == [threat_uuid]


def test_techniques_resolver_threat() -> None:
    threat_uuid = "00000000-0000-4000-8000-000000000040"
    threat = {
        "name": "Threat",
        "metadata": {"schema": "threat::1.0", "uuid": threat_uuid},
        "threat": {"att&ck": ["T1059", "T1003"]},
    }
    with (
        patch.object(fw, "MODELS_INDEX", {"threat": {threat_uuid: threat}}),
        patch("opentide.generation.framework.OpenTide") as mock_ot,
    ):
        mock_ot.Models.FlatIndex.get.return_value = threat
        techniques = fw.techniques_resolver(threat_uuid, recursive=False)
    assert techniques == ["T1059", "T1003"]


def test_childs_for_threat() -> None:
    threat_uuid = "00000000-0000-4000-8000-000000000050"
    objective_uuid = "00000000-0000-4000-8000-000000000051"
    objective = {
        "objective": {"threats": [threat_uuid]},
    }
    with (
        patch.object(
            fw,
            "MODELS_INDEX",
            {
                "threat": {threat_uuid: {"metadata": {"schema": "threat::1.0"}}},
                "objective": {objective_uuid: objective},
            },
        ),
        patch("opentide.generation.framework.OpenTide") as mock_ot,
    ):
        mock_ot.Models.FlatIndex.get.side_effect = lambda u, default=None: (
            {"metadata": {"schema": "threat::1.0"}}
            if u == threat_uuid
            else {"metadata": {"schema": "objective::1.0"}}
        )
        children = fw.childs(threat_uuid)
    assert objective_uuid in children


def test_chain_resolver_builds_tree() -> None:
    chaining = {"tvm-1": {"follows": ["tvm-2"]}, "tvm-2": {"follows": ["tvm-3"]}}
    with patch.object(fw, "CHAINING_INDEX", chaining):
        result = fw.chain_resolver("tvm-1")
    assert "tvm-1" in result
    assert "tvm-2" in result["tvm-1"]["follows"]
