"""Documentation publish path resolution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from opentide.documentation.publish.paths import page_path, targets


def test_targets_builds_object_directories(tmp_path: Path) -> None:
    ctx = MagicMock()
    ctx.output_dir = tmp_path / "docs"
    resolved = targets(ctx)
    assert resolved.output_root == ctx.output_dir
    assert resolved.rules_dir == ctx.output_dir / "Rules"
    assert resolved.objectives_dir == ctx.output_dir / "Objectives"
    assert resolved.threats_dir == ctx.output_dir / "Threats"


def test_page_path_with_and_without_uuid_permalinks(tmp_path: Path) -> None:
    ctx = MagicMock()
    ctx.uuid_permalinks = True
    ctx.formatter.page_filename.return_value = "rule-slug-uuid.md"
    path = page_path(ctx, folder=tmp_path / "Rules", name="My Rule", uuid="uuid-1")
    assert path == tmp_path / "Rules" / "rule-slug-uuid.md"
    ctx.formatter.page_filename.assert_called_once_with("my-rule", "uuid-1")

    ctx.formatter.reset_mock()
    ctx.uuid_permalinks = False
    ctx.formatter.page_filename.return_value = "rule-slug.md"
    path = page_path(ctx, folder=tmp_path / "Rules", name="My Rule", uuid="uuid-1")
    assert path.name == "rule-slug.md"
    ctx.formatter.page_filename.assert_called_once_with("my-rule", None)
