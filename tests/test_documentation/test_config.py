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
    assert settings.flavor is DocumentFlavor.github
    assert settings.folder_index_pages is True
    assert settings.uuid_permalinks is True
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
