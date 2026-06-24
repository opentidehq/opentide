"""VS Code snippet generation helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def _import_snippet_generator():
    paths = SimpleNamespace(
        Index={"templates": "/tmp/templates"},
        Tide=SimpleNamespace(snippet_file="/tmp/snippets.json"),
        Core=SimpleNamespace(subschemas="/tmp/subschemas"),
    )
    global_config = SimpleNamespace(
        metaschemas=["rule"],
        templates={"rule": "rule.yaml"},
        recomposition={},
    )
    with patch("opentide.core.registry.OpenTide") as mock_ot:
        mock_ot.Configurations.Global.Paths = paths
        mock_ot.Configurations.Global.recomposition = {}
        mock_ot.Configurations.Global.metaschemas = global_config.metaschemas
        mock_ot.Configurations.Global.templates = global_config.templates
        mock_ot.Configurations.Documentation.object_names = {"rule": "Rule"}
        mock_ot.Configurations.Index = {}
        from opentide.generation.vscode_snippets import vs_code_snippet_generator

        return vs_code_snippet_generator


def test_vs_code_snippet_generator_reads_template(tmp_path: Path) -> None:
    vs_code_snippet_generator = _import_snippet_generator()
    template = tmp_path / "rule.yaml"
    template.write_text("name: Example\n", encoding="utf-8")
    snippet = vs_code_snippet_generator(template, "Rule Template")
    assert snippet["prefix"] == "Rule Template"
    assert "name: Example" in snippet["body"]


def test_vs_code_snippet_generator_prepends_blank_lines(tmp_path: Path) -> None:
    vs_code_snippet_generator = _import_snippet_generator()
    template = tmp_path / "objective.yaml"
    template.write_text("objective:\n", encoding="utf-8")
    snippet = vs_code_snippet_generator(template, "Objective Template", blanks=2)
    assert snippet["body"][0] == ""
    assert snippet["body"][1] == ""
    assert "objective:" in snippet["body"][-1]
