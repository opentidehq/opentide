"""Tests for export playbook mapping."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def test_playbook_map_run_with_mocks(tmp_path: Path) -> None:
    from opentide.export import playbook_map

    output = tmp_path / "playbook.xlsx"
    with (
        patch.object(playbook_map, "OpenTide") as mock_tide,
        patch.dict(sys.modules, {"pandas": MagicMock()}),
    ):
        mock_pd = sys.modules["pandas"]
        frame = MagicMock()
        mock_pd.DataFrame.return_value = frame
        mock_tide.initialise = MagicMock()
        mock_tide.Models.rules = {
            "u1": {
                "status": "PRODUCTION",
                "title": "Rule",
                "meta": {"author": "Author"},
                "tags": {"playbook": "IR-001"},
            }
        }
        result = playbook_map.run(output=output)
    assert result == output
    frame.to_excel.assert_called_once()
