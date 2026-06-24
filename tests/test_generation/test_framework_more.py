"""Additional generation framework helper coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.generation import framework as fw


def test_rename_param_nest_rewrites_keys() -> None:
    nest = {"old_key": "value"}
    schema = MagicMock()
    with patch(
        "opentide.generation.pydantic_metaschema.lookup_schema_extra",
        return_value="new_key",
    ):
        result = fw.rename_param_nest(nest, schema)
    assert result == {"new_key": "value"}


def test_get_vocab_entry_legacy_identifier() -> None:
    entry = MagicMock()
    entry.as_dict.return_value = {"name": "Legacy"}
    entry.get.return_value = "Legacy"
    vocab = MagicMock()
    vocab.entries = {"Current": entry}
    entry.get.side_effect = lambda field: "legacy-id" if field == "legacy" else "Legacy"
    with patch.object(fw, "VOCAB_INDEX", {"surface": vocab}):
        assert fw.get_vocab_entry("surface", "legacy-id", field="name") == "Legacy"


def test_parents_for_signal() -> None:
    signal_uuid = "00000000-0000-4000-8000-000000000060"
    parent_uuid = "00000000-0000-4000-8000-000000000061"
    signal = {"metadata": {"schema": "signal::1.0"}, "parent": parent_uuid}
    with (
        patch("opentide.generation.framework.get_type", return_value="signal"),
        patch.object(fw, "MODELS_INDEX", {"signal": {signal_uuid: signal}}),
    ):
        assert fw.parents(signal_uuid) == [parent_uuid]


def test_childs_for_threat() -> None:
    threat_uuid = "00000000-0000-4000-8000-000000000070"
    objective_uuid = "00000000-0000-4000-8000-000000000071"
    objective = {"objective": {"threats": [threat_uuid]}}
    with (
        patch("opentide.generation.framework.get_type", return_value="threat"),
        patch.object(
            fw,
            "MODELS_INDEX",
            {"objective": {objective_uuid: objective}},
        ),
    ):
        assert fw.childs(threat_uuid) == [objective_uuid]


def test_relations_list_upstream_mode() -> None:
    parent_uuid = "00000000-0000-4000-8000-000000000080"
    with (
        patch("opentide.generation.framework.get_type", return_value="threat"),
        patch(
            "opentide.generation.framework.relations_upstream",
            return_value={parent_uuid: None},
        ),
        patch(
            "opentide.generation.framework.keep_active_rules",
            side_effect=lambda rules: rules,
        ),
    ):
        result = fw.relations_list("rule-1", mode="flat", direction="upstream")
    assert result["threat"] == [parent_uuid]


def test_relations_list_count_mode() -> None:
    with (
        patch("opentide.generation.framework.get_type", return_value="threat"),
        patch(
            "opentide.generation.framework.relations_downstream",
            return_value={"obj-1": {"obj-2": None}},
        ),
    ):
        result = fw.relations_list("threat-1", mode="count", direction="downstream")
    assert isinstance(result, dict)
