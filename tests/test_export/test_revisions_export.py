"""Revisions export builder."""

from __future__ import annotations

from unittest.mock import patch

from opentide.export import revisions_export


def test_build_revisions_export_collects_versions() -> None:
    sample_index = {
        "rule": {
            "u1": {
                "name": "Rule A",
                "description": "Detects X",
                "metadata": {
                    "version": "1.0",
                    "schema": "rule::1.0",
                    "modified": "2026-01-02",
                    "created": "2026-01-01",
                    "author": "analyst",
                },
            }
        }
    }
    with patch.object(revisions_export, "OpenTide") as mock_ot:
        mock_ot.initialise.return_value = None
        mock_ot.Configurations.Documentation.object_names = {"rule": "Detection Rules"}
        mock_ot.Configurations.Global.objects = ["rule"]
        mock_ot.Models.Index.get.return_value = sample_index["rule"]
        payload = revisions_export.build_revisions_export()
    assert "u1" in payload
    assert payload["u1"]["versions"]["1.0"]["schema"] == "rule::1.0"
    assert payload["u1"]["description"] == "Detects X"


def test_description_helpers_for_object_types() -> None:
    assert revisions_export._description({"description": "r"}, "rule") == "r"
    assert revisions_export._description({"threat": {"description": "t"}}, "threat") == "t"
    assert revisions_export._description({"objective": {"description": "o"}}, "objective") == "o"
    assert revisions_export._description({}, "unknown") == ""


def test_run_writes_export_file(tmp_path) -> None:
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    with patch.object(revisions_export, "OpenTide") as mock_ot:
        mock_ot.initialise.return_value = None
        mock_ot.Configurations.Global.exports.revisions = "revisions.export.json"
        mock_ot.Configurations.Global.Paths.Tide.exports = str(export_dir)
        with patch.object(revisions_export, "build_revisions_export", return_value={"u1": {}}):
            revisions_export.run()
    assert (export_dir / "revisions.export.json").is_file()
