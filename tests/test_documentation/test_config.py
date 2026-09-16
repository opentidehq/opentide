"""Documentation settings loader."""

from __future__ import annotations

from unittest.mock import patch

from opentide.documentation.config import load_settings
from opentide.documentation.types import DocumentFlavor


def test_load_settings_defaults() -> None:
    docs_cfg = {
        "output": "analytics/docs",
        "flavor": {"default": "github"},
        "folder_index_pages": True,
        "gitlab": {"uuid_permalinks": True},
        "diagrams": {"relations_direction": "both"},
        "index": {"relation_counts": True, "icons": True},
    }
    global_cfg = {"paths": {"core": {"docs_folder": "docs"}}}
    with patch("opentide.documentation.config.OpenTide") as mock_ot:
        mock_ot.Configurations.Documentation.Index = docs_cfg
        mock_ot.Configurations.Global.Index = global_cfg
        settings = load_settings()
    assert settings.output_dir.name == "docs"
    assert settings.output_dir.is_absolute()
    assert settings.flavor is DocumentFlavor.github
    assert settings.folder_index_pages is True
    assert settings.uuid_permalinks is False
    assert settings.relations_direction == "both"
    assert settings.index_relation_counts is True
    assert settings.index_icons is True


def test_load_settings_cli_overrides() -> None:
    with patch("opentide.documentation.config.OpenTide") as mock_ot:
        mock_ot.Configurations.Documentation.Index = {"flavor": "generic"}
        mock_ot.Configurations.Global.Index = {"paths": {"core": {}}}
        settings = load_settings(output="/tmp/out", flavor="gitlab")
    assert str(settings.output_dir) == "/tmp/out"
    assert settings.flavor is DocumentFlavor.gitlab
    assert settings.relations_direction == "both"
    assert settings.index_relation_counts is True
    assert settings.index_icons is False


def test_load_settings_uuid_permalinks_are_gitlab_only() -> None:
    """[gitlab] uuid_permalinks must not leak into GitHub or generic flavors (#203)."""
    docs_cfg = {
        "flavor": {"default": "github"},
        "gitlab": {"uuid_permalinks": True},
    }
    global_cfg = {"paths": {"core": {"docs_folder": "docs"}}}
    with patch("opentide.documentation.config.OpenTide") as mock_ot:
        mock_ot.Configurations.Documentation.Index = docs_cfg
        mock_ot.Configurations.Global.Index = global_cfg
        github = load_settings(flavor="github")
        generic = load_settings(flavor="generic")
        gitlab = load_settings(flavor="gitlab")
        azure = load_settings(flavor="azure-devops")
    assert github.uuid_permalinks is False
    assert generic.uuid_permalinks is False
    assert azure.uuid_permalinks is False
    assert gitlab.uuid_permalinks is True
