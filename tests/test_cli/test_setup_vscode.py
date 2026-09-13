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
    snippet_file_rel,
    validate_schema_fragment_matches_global,
    write_vscode_settings,
)

SNIPPET_REL = ".vscode/model-templates.code-snippets"


def test_snippet_file_rel_matches_paths_toml(tmp_path: Path) -> None:
    assert snippet_file_rel(workspace=tmp_path) == SNIPPET_REL


def test_build_yaml_schema_mappings() -> None:
    mappings = build_yaml_schema_mappings()
    assert mappings[".opentide/schemas/opentide.schema.json"] == "objects/**/*.yaml"


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
    assert ".opentide/schemas/opentide.schema.json" in settings["yaml.schemas"]


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
    assert SNIPPET_REL not in result["files"]


def test_run_vscode_snippets_writes_when_templates_exist(tmp_path: Path, monkeypatch) -> None:
    import sys
    import types

    templates = tmp_path / ".opentide" / "templates"
    templates.mkdir(parents=True)
    (templates / "rule.yaml").write_text("template: true\n", encoding="utf-8")

    fake_mod = types.ModuleType("vscode_snippets")
    fake_mod.SNIPPETS_PATH = SNIPPET_REL

    def fake_run() -> None:
        dest = tmp_path / SNIPPET_REL
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("{}", encoding="utf-8")

    fake_mod.run = fake_run
    monkeypatch.setitem(sys.modules, "opentide.generation.vscode_snippets", fake_mod)

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        rel = run_vscode_snippets(tmp_path)
    assert rel == SNIPPET_REL


def test_run_vscode_snippets_writes_with_real_generator(tmp_path: Path, monkeypatch) -> None:
    from tests.test_cli.conftest import _clear_runtime_caches

    from opentide.generation import vscode_snippets as vscode_snippets_mod

    templates = tmp_path / ".opentide" / "templates"
    templates.mkdir(parents=True)
    for name in (
        "rule.1.0.template.yaml",
        "threat.1.0.template.yaml",
        "objective.1.0.template.yaml",
    ):
        (templates / name).write_text(f"template: {name}\n", encoding="utf-8")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path))
    _clear_runtime_caches()
    vscode_snippets_mod.SNIPPETS_PATH = None
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        rel = run_vscode_snippets(tmp_path)
    assert rel == SNIPPET_REL
    payload = json.loads((tmp_path / SNIPPET_REL).read_text(encoding="utf-8"))
    assert "Detection Rules Template" in payload
    assert vscode_snippets_mod.SNIPPETS_PATH is None


def test_run_vscode_all_includes_snippets_when_generated(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.setup.vscode.run_vscode_snippets",
        lambda target: SNIPPET_REL,
    )
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_vscode_all(tmp_path)
    assert SNIPPET_REL in result["files"]


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


def test_build_yaml_schema_mappings_uses_router_schema() -> None:
    mappings = build_yaml_schema_mappings()
    assert len(mappings) == 1
    assert ".opentide/schemas/opentide.schema.json" in mappings


def test_run_vscode_snippets_file_not_found(tmp_path: Path, monkeypatch) -> None:
    from unittest.mock import MagicMock

    templates = tmp_path / ".opentide" / "templates"
    templates.mkdir(parents=True)
    (templates / "rule.yaml").write_text("x: 1\n", encoding="utf-8")

    import sys
    import types

    fake_mod = types.ModuleType("vscode_snippets")
    fake_mod.SNIPPETS_PATH = SNIPPET_REL
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
    os.environ.pop("OPENTIDE_TIDE_WORKSPACE", None)
    get_repo_root.cache_clear()

    templates = tmp_path / ".opentide" / "templates"
    templates.mkdir(parents=True)
    (templates / "rule.yaml").write_text("x: 1\n", encoding="utf-8")

    fake_mod = types.ModuleType("vscode_snippets")
    fake_mod.SNIPPETS_PATH = SNIPPET_REL
    fake_mod.run = lambda: (tmp_path / SNIPPET_REL).write_text("{}", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "opentide.generation.vscode_snippets", fake_mod)

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        run_vscode_snippets(tmp_path)

    assert "OPENTIDE_REPO_ROOT" not in os.environ
    assert "OPENTIDE_TIDE_WORKSPACE" not in os.environ
    get_repo_root.cache_clear()
