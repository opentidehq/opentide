"""Framework relation and rule filtering helpers."""

from __future__ import annotations

from unittest.mock import patch

from opentide.generation import framework as fw


def test_keep_active_rules_filters_deprecated() -> None:
    rules_index = {
        "u1": {
            "configurations": {
                "sentinel": {"status": "DEPRECATED"},
            }
        },
        "u2": {
            "configurations": {
                "sentinel": {"status": "STAGING"},
            }
        },
    }
    with (
        patch("opentide.generation.framework.OpenTide") as mock_ot,
        patch("opentide.deployment.check_status", side_effect=lambda s: s),
        patch("opentide.deployment.DEPRECATED_STATUSES", {"DEPRECATED"}),
    ):
        mock_ot.Models.Index = {"rule": rules_index}
        active = fw.keep_active_rules(["u1", "u2"])
    assert active == ["u2"]


def test_relations_list_downstream_flat_mode() -> None:
    with (
        patch("opentide.generation.framework.get_type", return_value="threat"),
        patch("opentide.generation.framework.childs", return_value=["obj-1"]),
        patch("opentide.generation.framework.relations_downstream", return_value={"obj-1": None}),
    ):
        result = fw.relations_list("threat-1", mode="flat", direction="downstream")
    assert result["threat"] == ["obj-1"]


def test_get_type_returns_signal_for_signal_index() -> None:
    uuid = "00000000-0000-4000-8000-000000000080"
    with patch("opentide.generation.framework.OpenTide") as mock_ot:
        mock_ot.Models.FlatIndex.get.return_value = {"metadata": {}, "name": "Signal"}
        mock_ot.Models.signals = {uuid: {}}
        assert fw.get_type(uuid, mute=True) == "signal"
