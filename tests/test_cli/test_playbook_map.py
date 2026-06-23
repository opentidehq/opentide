"""Tests for playbook map export."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.export.playbook_map import run


def test_playbook_map_run_writes_excel(tmp_path, monkeypatch) -> None:
    mock_mdr = {
        "uuid-1": {
            "status": "PRODUCTION",
            "title": "Test Rule",
            "meta": {"author": "author"},
            "tags": {"playbook": "PB-001"},
        }
    }

    mock_opentide = MagicMock()
    mock_opentide.Models.rules = mock_mdr

    mock_df = MagicMock()
    with (
        patch("opentide.export.playbook_map.OpenTide", mock_opentide),
        patch("pandas.DataFrame", return_value=mock_df),
    ):
        out = run(output=tmp_path / "map.xlsx")

    mock_df.to_excel.assert_called_once_with(tmp_path / "map.xlsx", index=False)
    assert out == tmp_path / "map.xlsx"
