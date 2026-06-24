"""Tests for deprecated VS Code setup module."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

from opentide.cli.services.setup.vscode import (
    build_yaml_schema_mappings,
    run_vscode_all,
    run_vscode_settings,
    run_vscode_snippets,
    validate_schema_fragment_matches_global,
    write_vscode_settings,
)


def test_build_yaml_schema_mappings() -> None:
    mappings = build_yaml_schema_mappings()
    assert mappings["Schemas/TVM Schema.json"] == "Objects/Threat Vectors/**/*.yaml"
    assert mappings["Schemas/Detection Objective.schema.json"] == (
        "Objects/Detection Objectives/**/*.yaml"
    )
    assert mappings["Schemas/MDR Schema.json"] == "Objects/Detection Rules/**/*.yaml"


def test_write_vscode_settings_merge(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "settings.json").write_text(
        json.dumps({"editor.tabSize": 4}),
        encoding="utf-8",
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        run_vscode_settings(tmp_path)
    assert caught
    settings = json.loads((vscode_dir / "settings.json").read_text(encoding="utf-8"))
    assert settings["editor.tabSize"] == 4
    assert "Schemas/MDR Schema.json" in settings["yaml.schemas"]


def test_schema_fragment_matches_global() -> None:
    validate_schema_fragment_matches_global()


def test_run_vscode_snippets_skips_without_templates(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        assert run_vscode_snippets(tmp_path) is None


def test_run_vscode_all_skips_snippets_on_empty_scaffold(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_vscode_all(tmp_path)
    assert ".vscode/settings.json" in result["files"]
    assert ".vscode/Model Templates.code-snippets" not in result["files"]


def test_run_vscode_snippets_writes_when_templates_exist(tmp_path: Path, monkeypatch) -> None:
    import sys
    import types

    templates = tmp_path / "Schemas" / "Templates"
    templates.mkdir(parents=True)
    (templates / "rule.yaml").write_text("template: true\n", encoding="utf-8")

    fake_mod = types.ModuleType("vscode_snippets")
    fake_mod.SNIPPETS_PATH = ".vscode/Model Templates.code-snippets"

    def fake_run() -> None:
        dest = tmp_path / ".vscode" / "Model Templates.code-snippets"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("{}", encoding="utf-8")

    fake_mod.run = fake_run
    monkeypatch.setitem(sys.modules, "opentide.generation.vscode_snippets", fake_mod)

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        rel = run_vscode_snippets(tmp_path)
    assert rel == ".vscode/Model Templates.code-snippets"


def test_run_vscode_all_includes_snippets_when_generated(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.setup.vscode.run_vscode_snippets",
        lambda target: ".vscode/Model Templates.code-snippets",
    )
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_vscode_all(tmp_path)
    assert ".vscode/Model Templates.code-snippets" in result["files"]


def test_write_vscode_settings_non_dict_yaml_schemas(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "settings.json").write_text(
        json.dumps({"yaml.schemas": "invalid"}),
        encoding="utf-8",
    )
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        write_vscode_settings(tmp_path)
    settings = json.loads((vscode_dir / "settings.json").read_text(encoding="utf-8"))
    assert isinstance(settings["yaml.schemas"], dict)


def test_build_yaml_schema_mappings_skips_unknown_object_type(monkeypatch) -> None:
    fake_config = {
        "paths": {"tide": {"rule": "Objects/Detection Rules/", "json_schemas": "Schemas/"}},
        "json_schemas": {"rule": "MDR Schema.json", "unknown_type": "Missing.schema.json"},
    }
    monkeypatch.setattr(
        "opentide.cli.services.setup.vscode.toml.loads",
        lambda _text: fake_config,
    )
    mappings = build_yaml_schema_mappings()
    assert "Schemas/MDR Schema.json" in mappings
    assert len(mappings) == 1


def test_run_vscode_snippets_file_not_found(tmp_path: Path, monkeypatch) -> None:
    from unittest.mock import MagicMock

    templates = tmp_path / "Schemas" / "Templates"
    templates.mkdir(parents=True)
    (templates / "rule.yaml").write_text("x: 1\n", encoding="utf-8")

    import sys
    import types

    fake_mod = types.ModuleType("vscode_snippets")
    fake_mod.SNIPPETS_PATH = ".vscode/Model Templates.code-snippets"
    fake_mod.run = MagicMock(side_effect=FileNotFoundError("missing template"))
    monkeypatch.setitem(sys.modules, "opentide.generation.vscode_snippets", fake_mod)

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        assert run_vscode_snippets(tmp_path) is None


def test_run_vscode_snippets_restores_unset_repo_root(tmp_path: Path, monkeypatch) -> None:
    import os
    import sys
    import types

    from opentide.core.root import get_repo_root

    os.environ.pop("OPENTIDE_REPO_ROOT", None)
    get_repo_root.cache_clear()

    templates = tmp_path / "Schemas" / "Templates"
    templates.mkdir(parents=True)
    (templates / "rule.yaml").write_text("x: 1\n", encoding="utf-8")

    fake_mod = types.ModuleType("vscode_snippets")
    fake_mod.SNIPPETS_PATH = ".vscode/Model Templates.code-snippets"
    fake_mod.run = lambda: (tmp_path / ".vscode" / "Model Templates.code-snippets").write_text(
        "{}", encoding="utf-8"
    )
    monkeypatch.setitem(sys.modules, "opentide.generation.vscode_snippets", fake_mod)

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        run_vscode_snippets(tmp_path)

    assert "OPENTIDE_REPO_ROOT" not in os.environ
    get_repo_root.cache_clear()
