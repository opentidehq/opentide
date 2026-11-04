"""Tests for deprecated VS Code setup module."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

from opentide.cli.services.setup.vscode import (
    _strip_jsonc,
    build_yaml_schema_mappings,
    is_opentide_schema_mapping,
    run_vscode_all,
    run_vscode_settings,
    run_vscode_setup,
    run_vscode_snippets,
    snippet_file_rel,
    write_vscode_extensions,
    write_vscode_settings,
)

SNIPPET_REL = ".vscode/model-templates.code-snippets"
ROUTER = ".opentide/schemas/opentide.schema.json"


def _object_folder_log_levels(stderr: str) -> list[str]:
    """Levels of ``could_not_find_object_folder`` JSON log lines (issue #212)."""
    levels: list[str] = []
    for line in stderr.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("event") == "could_not_find_object_folder":
            levels.append(str(record.get("level", "")))
    return levels


def test_snippet_file_rel_matches_paths_toml(tmp_path: Path) -> None:
    assert snippet_file_rel(workspace=tmp_path) == SNIPPET_REL


def test_build_yaml_schema_mappings_maps_objects_to_router() -> None:
    """Issue #550: one router mapping, so rule::1.0 and rule::1.1 coexist."""
    assert build_yaml_schema_mappings() == {ROUTER: "objects/**/*.yaml"}


def test_vscode_settings_writes_no_yaml_schemas(tmp_path: Path) -> None:
    """#752: the opentide extension's language server checks objects, not a YAML server."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "settings.json").write_text(
        json.dumps({"editor.tabSize": 4}),
        encoding="utf-8",
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = run_vscode_settings(tmp_path)
    assert not any(issubclass(item.category, DeprecationWarning) for item in caught)
    assert result["files"] == [".vscode/extensions.json"]
    settings = json.loads((vscode_dir / "settings.json").read_text(encoding="utf-8"))
    assert settings == {"editor.tabSize": 4}


def test_vscode_settings_creates_no_settings_file(tmp_path: Path) -> None:
    assert write_vscode_settings(tmp_path) is None
    assert not (tmp_path / ".vscode" / "settings.json").exists()


def test_vscode_settings_removes_the_router_mapping_and_keeps_the_rest(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "settings.json").write_text(
        json.dumps(
            {
                "editor.tabSize": 4,
                "yaml.schemas": {ROUTER: "objects/**/*.yaml", "other.json": "x/*.yaml"},
            }
        ),
        encoding="utf-8",
    )
    assert write_vscode_settings(tmp_path) == ".vscode/settings.json"
    settings = json.loads((vscode_dir / "settings.json").read_text(encoding="utf-8"))
    assert settings == {"editor.tabSize": 4, "yaml.schemas": {"other.json": "x/*.yaml"}}


def test_vscode_settings_drops_an_emptied_yaml_schemas(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "settings.json").write_text(
        json.dumps({"yaml.schemas": {"./" + ROUTER: ["objects/rules/**/*.yaml"]}}),
        encoding="utf-8",
    )
    assert write_vscode_settings(tmp_path) == ".vscode/settings.json"
    assert json.loads((vscode_dir / "settings.json").read_text(encoding="utf-8")) == {}


def test_vscode_settings_leaves_a_file_without_opentide_entries_untouched(
    tmp_path: Path,
) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    text = '{\n  // keep my comment\n  "yaml.schemas": {"other.json": "x/*.yaml"},\n}\n'
    (vscode_dir / "settings.json").write_text(text, encoding="utf-8")
    assert write_vscode_settings(tmp_path) is None
    assert (vscode_dir / "settings.json").read_text(encoding="utf-8") == text


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
    assert ".vscode/settings.json" not in result["files"]
    assert ".vscode/extensions.json" in result["files"]
    assert SNIPPET_REL not in result["files"]
    assert result["generated"] == []


def test_run_vscode_setup_creates_missing_nested_target(tmp_path: Path, monkeypatch) -> None:
    from tests.corpus_support import clear_runtime_caches

    missing = tmp_path / "new" / "detection-repo"
    assert not missing.exists()
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(missing))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(missing))
    clear_runtime_caches()
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_vscode_setup(missing)
    assert result["status"] == "completed"
    assert missing.is_dir()
    assert not (missing / ".vscode" / "settings.json").exists()
    assert (missing / ".vscode" / "extensions.json").is_file()
    assert (missing / ".opentide" / "templates" / "threat.1.0.template.yaml").is_file()
    assert (missing / SNIPPET_REL).is_file()


def test_run_vscode_setup_generate_writes_templates_schemas_and_snippets(
    tmp_path: Path, monkeypatch
) -> None:
    from tests.corpus_support import clear_runtime_caches

    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path))
    clear_runtime_caches()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = run_vscode_setup(tmp_path)
    deprecations = [item for item in caught if issubclass(item.category, DeprecationWarning)]
    assert len(deprecations) == 1
    assert result["status"] == "completed"
    assert result["generated"] == ["templates", "schemas"]
    assert (tmp_path / ".opentide" / "templates" / "threat.1.0.template.yaml").is_file()
    assert (tmp_path / ".opentide" / "schemas" / "opentide.schema.json").is_file()
    assert not (tmp_path / ".vscode" / "settings.json").exists()
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
    from tests.corpus_support import clear_runtime_caches

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
    clear_runtime_caches()
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


def test_run_vscode_setup_mcp_writes_mcp_json(tmp_path: Path, monkeypatch) -> None:
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
        without_mcp = run_vscode_setup(tmp_path, generate=False, mcp=False)
        with_mcp = run_vscode_setup(tmp_path / "mcp", generate=False, mcp=True)
    assert ".vscode/mcp.json" not in without_mcp["files"]
    assert not (tmp_path / ".vscode" / "mcp.json").exists()
    assert ".vscode/mcp.json" in with_mcp["files"]
    assert (tmp_path / "mcp" / ".vscode" / "mcp.json").is_file()
    # The same run recommends the extension, which provides the MCP server too (#752).
    assert with_mcp["extension_mcp"] is True
    assert "provides the opentide MCP server" in str(with_mcp["detail"])
    assert "extension_mcp" not in without_mcp


def test_run_vscode_setup_mcp_without_the_recommendation_says_nothing(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.setup.vscode.run_vscode_snippets",
        lambda target: SNIPPET_REL,
    )
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_vscode_setup(tmp_path, settings=False, generate=False, mcp=True)
    assert ".vscode/mcp.json" in result["files"]
    assert "extension_mcp" not in result


def test_write_vscode_settings_non_dict_yaml_schemas(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "settings.json").write_text(
        json.dumps({"yaml.schemas": "invalid"}),
        encoding="utf-8",
    )
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        assert write_vscode_settings(tmp_path) is None
    settings = json.loads((vscode_dir / "settings.json").read_text(encoding="utf-8"))
    assert settings == {"yaml.schemas": "invalid"}


def test_write_vscode_extensions_recommends_the_opentide_extension(tmp_path: Path) -> None:
    """#752: the opentide extension, not redhat.vscode-yaml."""
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        run_vscode_settings(tmp_path)
    extensions = json.loads((tmp_path / ".vscode" / "extensions.json").read_text(encoding="utf-8"))
    assert extensions["recommendations"] == ["opentidehq.opentide"]


def test_write_vscode_extensions_respects_unwanted_recommendations(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    text = json.dumps({"unwantedRecommendations": ["opentidehq.opentide"]})
    (vscode_dir / "extensions.json").write_text(text, encoding="utf-8")
    # The extension is unwanted: nothing to add, so the file is not written.
    assert write_vscode_extensions(tmp_path) is None
    assert (vscode_dir / "extensions.json").read_text(encoding="utf-8") == text


def test_write_vscode_extensions_merges_recommendations(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "extensions.json").write_text(
        json.dumps({"recommendations": ["ms-python.python"]}),
        encoding="utf-8",
    )
    write_vscode_extensions(tmp_path)
    extensions = json.loads((vscode_dir / "extensions.json").read_text(encoding="utf-8"))
    assert extensions["recommendations"] == ["ms-python.python", "opentidehq.opentide"]


def test_write_vscode_extensions_non_list_recommendations(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "extensions.json").write_text(
        json.dumps({"recommendations": "invalid"}),
        encoding="utf-8",
    )
    write_vscode_extensions(tmp_path)
    extensions = json.loads((vscode_dir / "extensions.json").read_text(encoding="utf-8"))
    assert extensions["recommendations"] == ["opentidehq.opentide"]


def test_build_yaml_schema_mappings_lists_folders_without_common_parent(monkeypatch) -> None:
    from opentide.core.files import resolve_configurations

    configs = resolve_configurations()
    cfg = dict(configs["paths"])
    cfg["paths"] = {
        **cfg["paths"],
        "objects": {"threat": "intel/threats/", "objective": "objectives/", "rule": "rules/"},
    }
    monkeypatch.setattr(
        "opentide.cli.services.setup.vscode.resolve_configurations",
        lambda: {**configs, "paths": cfg},
    )
    assert build_yaml_schema_mappings() == {
        ROUTER: ["intel/threats/**/*.yaml", "objectives/**/*.yaml", "rules/**/*.yaml"]
    }


def test_write_vscode_settings_drops_every_mapping_opentide_wrote(tmp_path: Path) -> None:
    """The router (#752) and the per-folder revision mappings of earlier releases (#550)."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "settings.json").write_text(
        """{
  // user comment survives parsing
  "editor.tabSize": 2,
  "yaml.schemas": {
    ".opentide/schemas/threat.1.0.schema.json": "objects/threats/**/*.yaml",
    ".opentide/schemas/objective.1.0.schema.json": "objects/objectives/*.yaml",
    ".opentide/schemas/rule.1.1.schema.json": "objects/rules/**/*.yaml",
    "./.opentide/schemas/rule.1.0.schema.json": ["objects/rules/*.yaml"],
    ".opentide/schemas/opentide.schema.json": "objects/rules/**/*.yaml",
    ".opentide/schemas/rule.1.0.schema.json": "legacy/rules/*.yaml",
    ".opentide/schemas/visibility.1.0.schema.json": "visibility/*.yaml",
    "https://json.schemastore.org/github-workflow.json": ".github/workflows/*.yml",
  },
}
""",
        encoding="utf-8",
    )
    write_vscode_settings(tmp_path)
    text = (vscode_dir / "settings.json").read_text(encoding="utf-8")
    assert "// user comment survives parsing" in text
    settings = json.loads(_strip_jsonc(text))
    assert settings["editor.tabSize"] == 2
    assert settings["yaml.schemas"] == {
        ".opentide/schemas/rule.1.0.schema.json": "legacy/rules/*.yaml",
        ".opentide/schemas/visibility.1.0.schema.json": "visibility/*.yaml",
        "https://json.schemastore.org/github-workflow.json": ".github/workflows/*.yml",
    }


def test_write_vscode_settings_is_idempotent(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "settings.json").write_text(
        json.dumps({"yaml.schemas": {ROUTER: "objects/**/*.yaml", "o.json": "o/*.yaml"}}),
        encoding="utf-8",
    )
    assert write_vscode_settings(tmp_path) == ".vscode/settings.json"
    first = (vscode_dir / "settings.json").read_text(encoding="utf-8")
    assert write_vscode_settings(tmp_path) is None
    assert (vscode_dir / "settings.json").read_text(encoding="utf-8") == first


def test_setup_vscode_no_merge_keeps_the_settings_of_the_user(tmp_path: Path) -> None:
    """--no-merge replaces extensions.json; settings.json has nothing of opentide's to write."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    user = {"editor.tabSize": 4, "yaml.schemas": {"other.schema.json": "other/*.yaml"}}
    (vscode_dir / "settings.json").write_text(json.dumps(user), encoding="utf-8")
    (vscode_dir / "extensions.json").write_text(
        json.dumps({"recommendations": ["redhat.vscode-yaml"]}), encoding="utf-8"
    )
    run_vscode_settings(tmp_path, merge=False)
    assert json.loads((vscode_dir / "settings.json").read_text(encoding="utf-8")) == user
    extensions = json.loads((vscode_dir / "extensions.json").read_text(encoding="utf-8"))
    assert extensions == {"recommendations": ["opentidehq.opentide"]}


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
    from tests.corpus_support import clear_runtime_caches
    from tests.test_cli.conftest import assert_json_ok
    from typer.testing import CliRunner

    from opentide.cli import app
    from opentide.registry.builder import reset_missing_object_folder_log_cache

    reset_missing_object_folder_log_cache()
    clear_runtime_caches()
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--json", "--repo", str(tmp_path), "setup", "vscode", str(tmp_path)],
    )
    payload = assert_json_ok(result)
    assert payload["status"] == "completed"
    assert "error" not in _object_folder_log_levels(result.stderr)
    assert (tmp_path / ".vscode" / "extensions.json").is_file()
    assert (tmp_path / SNIPPET_REL).is_file()


def test_run_vscode_setup_empty_dir_debug_logs_missing_folders_at_debug(
    tmp_path: Path,
) -> None:
    """With --debug, absent objects/* still must not log at error (issue #212)."""
    from tests.test_cli.conftest import assert_json_ok
    from typer.testing import CliRunner

    from opentide.cli import app
    from opentide.registry.builder import reset_missing_object_folder_log_cache

    reset_missing_object_folder_log_cache()
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--json", "--debug", "--repo", str(tmp_path), "setup", "vscode", str(tmp_path)],
    )
    payload = assert_json_ok(result)
    assert payload["status"] == "completed"
    levels = _object_folder_log_levels(result.stderr)
    assert levels
    assert "error" not in levels
    assert all(level == "debug" for level in levels)


def test_run_vscode_setup_empty_object_dirs_still_quiet(
    tmp_path: Path,
) -> None:
    from tests.corpus_support import clear_runtime_caches
    from tests.test_cli.conftest import assert_json_ok
    from typer.testing import CliRunner

    from opentide.cli import app
    from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup
    from opentide.registry.builder import reset_missing_object_folder_log_cache

    reset_missing_object_folder_log_cache()
    clear_runtime_caches()
    run_repo_setup(RepoSetupOptions(path=tmp_path, name="Empty objects", yes=True))
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--json", "--repo", str(tmp_path), "setup", "vscode", str(tmp_path)],
    )
    payload = assert_json_ok(result)
    assert payload["status"] == "completed"
    assert "error" not in _object_folder_log_levels(result.stderr)


def test_the_deprecation_is_a_warning_line_not_an_event_slug(capsys, monkeypatch) -> None:
    """It printed "warning: Vscode setup deprecated · detail: opentide setup vscode is
    deprecated …", the log event's slug (post-merge end-to-end run)."""
    from opentide.cli.services.setup import vscode
    from opentide.cli.ui.mode import OutputMode, set_mode

    set_mode(OutputMode.PLAIN)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            vscode.emit_vscode_deprecation()
    finally:
        set_mode(None)
    err = capsys.readouterr().err
    assert err.startswith("warning: opentide setup vscode is deprecated and will be removed")
    assert "Vscode setup deprecated" not in err
    assert "detail:" not in err


@pytest.mark.parametrize(
    "value",
    [
        "objects/**/*.yaml",
        ["objects/**/*.yaml"],
        ["./objects/**/*.yaml", "objects/rules/*.yaml"],
        "objects/rules/*.yaml",
    ],
)
def test_write_vscode_settings_removes_the_router_mapping_as_a_string_or_in_a_list(
    tmp_path: Path, value: object
) -> None:
    """The YAML extension takes the glob as a string or in a list; either form of the
    router mapping an earlier release wrote is removed (#752), the other settings kept."""
    settings = tmp_path / ".vscode" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps({"editor.tabSize": 2, "yaml.schemas": {ROUTER: value, "own.json": "x.yaml"}}),
        encoding="utf-8",
    )

    assert write_vscode_settings(tmp_path) == ".vscode/settings.json"
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "editor.tabSize": 2,
        "yaml.schemas": {"own.json": "x.yaml"},
    }


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        (["hunts/**/*.yaml", "./objects/**/*.yaml"], ["hunts/**/*.yaml"]),
        (["objects/**/*.yaml", "playbooks/**/*.yaml"], ["playbooks/**/*.yaml"]),
        ("playbooks/**/*.yaml", "playbooks/**/*.yaml"),
    ],
)
def test_write_vscode_settings_keeps_the_users_own_globs_on_the_router(
    tmp_path: Path, value: object, kept: object
) -> None:
    """Only the globs opentide wrote go; a folder the user mapped to the router stays."""
    settings = tmp_path / ".vscode" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"yaml.schemas": {ROUTER: value}}), encoding="utf-8")
    write_vscode_settings(tmp_path)
    assert json.loads(settings.read_text(encoding="utf-8")) == {"yaml.schemas": {ROUTER: kept}}
    assert not is_opentide_schema_mapping(ROUTER, kept)


@pytest.mark.parametrize(
    "content",
    [
        b'\xef\xbb\xbf{\r\n  "editor.tabSize": 2\r\n}\r\n',
        b'{ "editor.tabSize": 2, oops }\n',
    ],
    ids=["bom", "unparsable"],
)
def test_setup_vscode_leaves_a_settings_file_it_cannot_read_and_carries_on(
    tmp_path: Path, content: bytes
) -> None:
    from tests.corpus_support import clear_runtime_caches
    from typer.testing import CliRunner

    from opentide.cli import app

    settings = tmp_path / ".vscode" / "settings.json"
    settings.parent.mkdir()
    settings.write_bytes(content)
    clear_runtime_caches()
    result = CliRunner().invoke(
        app, ["--json", "--repo", str(tmp_path), "setup", "vscode", str(tmp_path)]
    )
    clear_runtime_caches()
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert settings.read_bytes() == content
    assert (tmp_path / SNIPPET_REL).is_file()
    assert (tmp_path / ".vscode" / "extensions.json").is_file()
    unreadable = [w for w in payload.get("warnings") or [] if "settings.json" in w]
    assert bool(unreadable) == (content[:3] != b"\xef\xbb\xbf")


def test_an_unreadable_extensions_json_is_left_unchanged(tmp_path: Path) -> None:
    extensions = tmp_path / ".vscode" / "extensions.json"
    extensions.parent.mkdir()
    extensions.write_bytes(b"{ not json\n")
    warnings: list[str] = []
    assert write_vscode_extensions(tmp_path, warnings=warnings) is None
    assert extensions.read_bytes() == b"{ not json\n"
    assert warnings and "extensions.json" in warnings[0]


VSCODE_TEMPLATE = (
    "{\r\n"
    "\t// See https://go.microsoft.com/fwlink/?LinkId=827846 to learn about workspace "
    "recommendations.\r\n"
    "\t// Extension identifier format: ${publisher}.${name}.\r\n"
    '\t"recommendations": [\r\n'
    '\t\t"ms-python.python"\r\n'
    "\t]\r\n"
    "}\r\n"
)


def test_an_extensions_json_that_recommends_the_extension_is_not_rewritten(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".vscode" / "extensions.json"
    path.parent.mkdir()
    original = VSCODE_TEMPLATE.replace('"ms-python.python"', '"opentidehq.opentide"').encode()
    path.write_bytes(original)
    assert write_vscode_extensions(tmp_path) is None
    assert path.read_bytes() == original


def test_merging_into_a_commented_crlf_extensions_json_keeps_it(tmp_path: Path) -> None:
    path = tmp_path / ".vscode" / "extensions.json"
    path.parent.mkdir()
    path.write_bytes(VSCODE_TEMPLATE.encode())
    assert write_vscode_extensions(tmp_path) == ".vscode/extensions.json"
    assert (
        path.read_bytes()
        == VSCODE_TEMPLATE.replace(
            '\t\t"ms-python.python"\r\n',
            '\t\t"ms-python.python",\r\n\t\t"opentidehq.opentide"\r\n',
        ).encode()
    )


def test_an_extensions_json_without_recommendations_gains_them_in_place(tmp_path: Path) -> None:
    path = tmp_path / ".vscode" / "extensions.json"
    path.parent.mkdir()
    path.write_bytes(b'{\n  // ours\n  "unwantedRecommendations": ["x.y"]\n}\n')
    write_vscode_extensions(tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "// ours" in text
    assert json.loads(_strip_jsonc(text)) == {
        "recommendations": ["opentidehq.opentide"],
        "unwantedRecommendations": ["x.y"],
    }


def test_removing_the_mapping_keeps_comments_crlf_and_a_bom(tmp_path: Path) -> None:
    path = tmp_path / ".vscode" / "settings.json"
    path.parent.mkdir()
    original = (
        "\ufeff{\r\n"
        "  // team settings\r\n"
        '  "editor.tabSize": 2,\r\n'
        '  "yaml.schemas": {\r\n'
        f'    "{ROUTER}": "objects/**/*.yaml" // keep me\r\n'
        "  }\r\n"
        "}\r\n"
    )
    path.write_bytes(original.encode("utf-8"))
    assert write_vscode_settings(tmp_path) == ".vscode/settings.json"
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    assert "// team settings" in text
    assert "\n" not in text.replace("\r\n", "")
    assert json.loads(_strip_jsonc(text)) == {"editor.tabSize": 2}


def test_rewriting_a_router_mapping_in_place_keeps_the_rest_of_the_file(tmp_path: Path) -> None:
    path = tmp_path / ".vscode" / "settings.json"
    path.parent.mkdir()
    original = (
        "{\n"
        '  "yaml.schemas": {\n'
        '    "other.json": "x/*.yaml", // theirs\n'
        f'    "{ROUTER}": ["playbooks/**/*.yaml", "objects/**/*.yaml"],\n'
        "  },\n"
        "  /* block */\n"
        '  "editor.tabSize": 4,\n'
        "}\n"
    )
    path.write_text(original, encoding="utf-8")
    write_vscode_settings(tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "// theirs" in text and "/* block */" in text
    assert json.loads(_strip_jsonc(text)) == {
        "yaml.schemas": {"other.json": "x/*.yaml", ROUTER: ["playbooks/**/*.yaml"]},
        "editor.tabSize": 4,
    }
