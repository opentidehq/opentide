"""Workspace path aliases for the in-memory registry."""

from __future__ import annotations

from pathlib import Path

from opentide.registry.paths import legacy_path_aliases


def _minimal_paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "opentide": tmp_path / ".opentide",
        "threat": tmp_path / "objects/threats",
        "objective": tmp_path / "objects/objectives",
        "rule": tmp_path / "objects/rules",
        "json_schemas": tmp_path / ".opentide/schemas",
        "templates": tmp_path / ".opentide/templates",
        "exports": tmp_path / ".opentide/exports",
        "snippet_file": tmp_path / ".vscode/model-templates.code-snippets",
        "vocabularies": tmp_path / "vocabulary",
        "resources": tmp_path / "external",
        "log_sources": tmp_path / "log_sources",
        "platform_configs": tmp_path / "platforms",
        "platform_templates": tmp_path / "platform_templates",
        "docs_folder": tmp_path / "docs",
        "rules_docs_folder": tmp_path / "docs/rules",
        "objectives_docs_folder": tmp_path / "docs/objectives",
        "threats_docs_folder": tmp_path / "docs/threats",
    }


def test_legacy_core_paths_alias_subschemas_to_platform_templates(tmp_path: Path) -> None:
    aliases = legacy_path_aliases(_minimal_paths(tmp_path))
    assert aliases["core"]["subschemas"] == tmp_path / "platform_templates"
    assert aliases["core"]["platform_templates"] == aliases["core"]["subschemas"]
