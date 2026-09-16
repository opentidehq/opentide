"""Documentation publish path resolution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from opentide.documentation.format.github import GitHubFormatter
from opentide.documentation.format.gitlab import GitLabFormatter
from opentide.documentation.publish.paths import page_path, targets


def test_targets_builds_object_directories(tmp_path: Path) -> None:
    ctx = MagicMock()
    ctx.output_dir = tmp_path / "docs"
    resolved = targets(ctx)
    assert resolved.output_root == ctx.output_dir
    assert resolved.rules_dir == ctx.output_dir / "rules"
    assert resolved.objectives_dir == ctx.output_dir / "objectives"
    assert resolved.threats_dir == ctx.output_dir / "threats"


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


def test_page_path_github_uses_slug_even_if_uuid_permalinks_set(tmp_path: Path) -> None:
    ctx = MagicMock()
    ctx.uuid_permalinks = True
    ctx.formatter = GitHubFormatter()
    path = page_path(ctx, folder=tmp_path / "threats", name="Simulated Actor", uuid="abc-uuid")
    assert path == tmp_path / "threats" / "simulated-actor.md"


def test_page_path_gitlab_uuid_permalinks_use_uuid_filename(tmp_path: Path) -> None:
    ctx = MagicMock()
    ctx.uuid_permalinks = True
    ctx.formatter = GitLabFormatter()
    path = page_path(ctx, folder=tmp_path / "threats", name="Simulated Actor", uuid="abc-uuid")
    assert path == tmp_path / "threats" / "abc-uuid.md"
