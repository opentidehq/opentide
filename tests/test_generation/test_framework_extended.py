"""Extended generation framework helper coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.generation import framework as fw


def test_vocab_metadata_missing_vocab() -> None:
    with patch.object(fw, "VOCAB_INDEX", {}):
        assert fw.vocab_metadata("missing") == ""


def test_vocab_metadata_with_field() -> None:
    vocab = MagicMock()
    vocab.metadata.get.return_value = "icon-value"
    with patch.object(fw, "VOCAB_INDEX", {"severity": vocab}):
        assert fw.vocab_metadata("severity", field="icon") == "icon-value"


def test_get_vocab_stage_details() -> None:
    vocab = MagicMock()
    vocab.metadata.get.return_value = [{"id": "core", "name": "Core", "description": "Base"}]
    with patch.object(fw, "VOCAB_INDEX", {"surface": vocab}):
        details = fw.get_vocab_stage_details("surface", "core")
    assert details == ("Core", "Base")


def test_get_vocab_entry_and_legacy_lookup() -> None:
    entry = MagicMock()
    entry.as_dict.return_value = {"name": "Windows"}
    entry.get.return_value = "Windows"
    vocab = MagicMock()
    vocab.entries = {"Windows::Desktop": entry}
    with patch.object(fw, "VOCAB_INDEX", {"surface": vocab}):
        assert fw.get_vocab_entry("surface", "Windows::Desktop") == {"name": "Windows"}
        assert fw.get_vocab_entry("surface", "Windows::Desktop", field="name") == "Windows"


def test_get_key_in_model_body_nested() -> None:
    body = {"outer": {"inner": {"target": "value"}}}
    assert fw.get_key_in_model_body(body, "target") == "value"
    assert fw.get_key_in_model_body(body, "missing") is None


def test_model_value_reads_nested_key() -> None:
    uuid = "00000000-0000-4000-8000-000000000070"
    payload = {"metadata": {"schema": "rule::1.0"}, "description": "Detects"}
    with (
        patch.object(fw, "MODELS_INDEX", {"rule": {uuid: payload}}),
        patch("opentide.generation.framework.OpenTide") as mock_ot,
    ):
        mock_ot.Models.FlatIndex.get.return_value = payload
        assert fw.model_value(uuid, "description") == "Detects"


def test_parents_returns_empty_for_unknown_type() -> None:
    with (
        patch("opentide.generation.framework.get_type", return_value="unknown"),
        patch.object(fw, "MODELS_INDEX", {}),
    ):
        assert fw.parents("uuid") == []


def test_childs_returns_empty_for_rule_type() -> None:
    with patch("opentide.generation.framework.get_type", return_value="rule"):
        assert fw.childs("uuid") == []
