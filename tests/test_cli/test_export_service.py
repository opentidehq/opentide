"""CLI export service behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.enums import ExportTarget
from opentide.cli.services import export as export_service


@pytest.mark.parametrize(
    ("target", "patch_target"),
    [
        (ExportTarget.navigator, "opentide.export.attack_navigator_layer.run"),
        (ExportTarget.objects, "opentide.export.table_export.TableExporter"),
        (ExportTarget.revisions, "opentide.export.revisions_export.run"),
    ],
)
def test_run_export_target_delegates(target: ExportTarget, patch_target: str) -> None:
    if target is ExportTarget.objects:
        mock_instance = MagicMock()
        with patch(patch_target, return_value=mock_instance):
            export_service.run_export_target(target)
        mock_instance.run.assert_called_once()
        return
    with patch(patch_target) as mock_run:
        export_service.run_export_target(target)
    mock_run.assert_called_once()


def test_run_export_target_unknown_raises() -> None:
    with pytest.raises(ValueError, match="Unknown export target"):
        export_service.run_export_target("invalid")  # type: ignore[arg-type]


def test_run_export_returns_payload() -> None:
    ctx = CliContext(json_output=True)
    with patch.object(export_service, "run_export_target") as mock_target:
        result = export_service.run_export(ctx, target=ExportTarget.revisions)
    mock_target.assert_called_once_with(ExportTarget.revisions)
    assert result["target"] == "revisions"
