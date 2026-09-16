"""Tests for deprecated VS Code setup module."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

from opentide.cli.services.setup.vscode import (
    build_yaml_schema_mappings,
    run_vscode_all,
    run_vscode_settings,
    run_vscode_setup,
    run_vscode_snippets,
    snippet_file_rel,
    validate_schema_fragment_matches_global,
    write_vscode_extensions,
    write_vscode_settings,
)

SNIPPET_REL = ".vscode/model-templates.code-snippets"


def test_snippet_file_rel_matches_paths_toml(tmp_path: Path) -> None:
    assert snippet_file_rel(workspace=tmp_path) == SNIPPET_REL


def test_build_yaml_schema_mappings() -> None:
    mappings = build_yaml_schema_mappings()
    assert mappings[".opentide/schemas/threat.1.0.schema.json"] == "objects/threats/**/*.yaml"
    assert mappings[".opentide/schemas/objective.1.0.schema.json"] == "objects/objectives/**/*.yaml"
    assert mappings[".opentide/schemas/rule.1.0.schema.json"] == "objects/rules/**/*.yaml"
    assert ".opentide/schemas/opentide.schema.json" not in mappings
    assert "objects/**/*.yaml" not in mappings.values()


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
    assert not any(issubclass(item.category, DeprecationWarning) for item in caught)
    settings = json.loads((vscode_dir / "settings.json").read_text(encoding="utf-8"))
    assert settings["editor.tabSize"] == 4
    assert ".opentide/schemas/threat.1.0.schema.json" in settings["yaml.schemas"]
    assert settings["yaml.schemas"][".opentide/schemas/threat.1.0.schema.json"] == (
        "objects/threats/**/*.yaml"
    )


def test_schema_fragment_matches_global() -> None:
    validate_schema_fragment_matches_global()


def test_run_vscode_snippets_skips_without_templates(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        assert run_vscode_snippets(tmp_path) is None


def test_run_vscode_setup_no_generate_fails_without_templates(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_vscode_setup(tmp_path, generate=False)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert ".vscode/settings.json" in result["files"]
    assert ".vscode/extensions.json" in result["files"]
    assert SNIPPET_REL not in result["files"]
    assert result["generated"] == []


def test_run_vscode_setup_creates_missing_nested_target(tmp_path: Path) -> None:
    missing = tmp_path / "new" / "detection-repo"
    assert not missing.exists()
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_vscode_setup(missing)
    assert result["status"] == "completed"
    assert missing.is_dir()
    assert (missing / ".vscode" / "settings.json").is_file()
    assert (missing / ".vscode" / "extensions.json").is_file()
    assert (missing / ".opentide" / "templates" / "threat.1.0.template.yaml").is_file()
    assert (missing / SNIPPET_REL).is_file()


def test_run_vscode_setup_generate_writes_templates_schemas_and_snippets(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = run_vscode_setup(tmp_path)
    deprecations = [item for item in caught if issubclass(item.category, DeprecationWarning)]
    assert len(deprecations) == 1
    assert result["status"] == "completed"
    assert result["generated"] == ["templates", "schemas"]
    assert (tmp_path / ".opentide" / "templates" / "threat.1.0.template.yaml").is_file()
    assert (tmp_path / ".opentide" / "schemas" / "opentide.schema.json").is_file()
    assert (tmp_path / ".vscode" / "settings.json").is_file()
    assert (tmp_path / SNIPPET_REL).is_file()
    assert SNIPPET_REL in result["files"]
    assert ".vscode/extensions.json" in result["files"]


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
        "opentide.cli.services.generation.run_generate_phases_for_workspace",
        lambda target, phases: list(phases),
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.vscode.run_vscode_snippets",
        lambda target: SNIPPET_REL,
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = run_vscode_all(tmp_path)
    deprecations = [item for item in caught if issubclass(item.category, DeprecationWarning)]
    assert len(deprecations) == 1
    assert SNIPPET_REL in result["files"]
    assert result["generated"] == ["templates", "schemas"]


def test_run_vscode_setup_settings_only_generates_schemas(tmp_path: Path, monkeypatch) -> None:
    recorded: list[str] = []
    monkeypatch.setattr(
        "opentide.cli.services.generation.run_generate_phases_for_workspace",
        lambda target, phases: recorded.extend(phases) or list(phases),
    )
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_vscode_setup(tmp_path, settings=True, snippets=False)
    assert recorded == ["schemas"]
    assert result["status"] == "completed"
    assert SNIPPET_REL not in result["files"]


def test_run_vscode_setup_snippets_only_generates_templates(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.generation.run_generate_phases_for_workspace",
        lambda target, phases: list(phases),
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.vscode.run_vscode_snippets",
        lambda target: SNIPPET_REL,
    )
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_vscode_setup(tmp_path, settings=False, snippets=True)
    assert result["generated"] == ["templates"]
    assert result["status"] == "completed"
    assert result["files"] == [SNIPPET_REL]


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


def test_write_vscode_extensions_recommends_yaml_extension(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        run_vscode_settings(tmp_path)
    extensions = json.loads((tmp_path / ".vscode" / "extensions.json").read_text(encoding="utf-8"))
    assert "redhat.vscode-yaml" in extensions["recommendations"]


def test_write_vscode_extensions_merges_recommendations(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "extensions.json").write_text(
        json.dumps({"recommendations": ["ms-python.python"]}),
        encoding="utf-8",
    )
    write_vscode_extensions(tmp_path)
    extensions = json.loads((vscode_dir / "extensions.json").read_text(encoding="utf-8"))
    assert extensions["recommendations"] == ["ms-python.python", "redhat.vscode-yaml"]


def test_write_vscode_extensions_non_list_recommendations(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "extensions.json").write_text(
        json.dumps({"recommendations": "invalid"}),
        encoding="utf-8",
    )
    write_vscode_extensions(tmp_path)
    extensions = json.loads((vscode_dir / "extensions.json").read_text(encoding="utf-8"))
    assert extensions["recommendations"] == ["redhat.vscode-yaml"]


def test_build_yaml_schema_mappings_uses_per_folder_schemas() -> None:
    mappings = build_yaml_schema_mappings()
    assert len(mappings) == 3
    assert ".opentide/schemas/opentide.schema.json" not in mappings
    assert set(mappings.values()) == {
        "objects/threats/**/*.yaml",
        "objects/objectives/**/*.yaml",
        "objects/rules/**/*.yaml",
    }
    assert all(glob.endswith("/**/*.yaml") for glob in mappings.values())


def test_write_vscode_settings_replaces_legacy_router_wildcard(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "settings.json").write_text(
        json.dumps(
            {
                "yaml.schemas": {
                    ".opentide/schemas/opentide.schema.json": "objects/**/*.yaml",
                    "other.schema.json": "other/*.yaml",
                }
            }
        ),
        encoding="utf-8",
    )
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        write_vscode_settings(tmp_path)
    settings = json.loads((vscode_dir / "settings.json").read_text(encoding="utf-8"))
    schemas = settings["yaml.schemas"]
    assert ".opentide/schemas/opentide.schema.json" not in schemas
    assert schemas[".opentide/schemas/rule.1.0.schema.json"] == "objects/rules/**/*.yaml"
    assert schemas["other.schema.json"] == "other/*.yaml"


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


def test_run_vscode_setup_empty_dir_completes_without_object_folder_errors(
    tmp_path: Path,
) -> None:
    """Issue #212: missing objects/* during generate-first vscode setup is not an error."""
    from tests.test_cli.conftest import assert_json_ok
    from typer.testing import CliRunner

    from opentide.cli import app
    from opentide.registry.builder import reset_missing_object_folder_log_cache

    reset_missing_object_folder_log_cache()
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--json", "--repo", str(tmp_path), "setup", "vscode", str(tmp_path)],
    )
    payload = assert_json_ok(result)
    assert payload["status"] == "completed"
    assert "could_not_find_object_folder" not in result.stderr
    assert (tmp_path / ".vscode" / "settings.json").is_file()
    assert (tmp_path / SNIPPET_REL).is_file()


def test_run_vscode_setup_empty_object_dirs_still_quiet(
    tmp_path: Path,
) -> None:
    from tests.test_cli.conftest import assert_json_ok
    from typer.testing import CliRunner

    from opentide.cli import app
    from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup
    from opentide.registry.builder import reset_missing_object_folder_log_cache

    reset_missing_object_folder_log_cache()
    run_repo_setup(RepoSetupOptions(path=tmp_path, name="Empty objects", yes=True))
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--json", "--repo", str(tmp_path), "setup", "vscode", str(tmp_path)],
    )
    payload = assert_json_ok(result)
    assert payload["status"] == "completed"
    assert "could_not_find_object_folder" not in result.stderr
