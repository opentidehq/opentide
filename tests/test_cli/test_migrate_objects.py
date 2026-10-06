"""Tests for ``opentide migrate objects``."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.migrate_objects import run_migrate_objects

runner = CliRunner()


def _legacy_repo(tmp_path: Path) -> Path:
    root = tmp_path / "legacy"
    (root / "Configurations" / "platforms").mkdir(parents=True)
    (root / "Configurations" / "platforms" / "sentinel.toml").write_text(
        "enabled = true\n", encoding="utf-8"
    )
    (root / ".opentide" / "framework" / "schemas").mkdir(parents=True)
    (root / ".opentide" / "framework" / "schemas" / "rule.schema.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (root / ".opentide" / "framework" / "templates").mkdir(parents=True)
    (root / ".opentide" / "framework" / "templates" / "rule.template.yaml").write_text(
        "name: x\n", encoding="utf-8"
    )
    (root / "Objects" / "Threat Vectors").mkdir(parents=True)
    (root / "Objects" / "Threat Vectors" / "threat.yaml").write_text("name: t\n", encoding="utf-8")
    (root / "Objects" / "Detection Objectives").mkdir(parents=True)
    (root / "Objects" / "Detection Objectives" / "objective.yaml").write_text(
        "name: o\n", encoding="utf-8"
    )
    (root / "Objects" / "Detection Rules").mkdir(parents=True)
    (root / "Objects" / "Detection Rules" / "rule.yaml").write_text("name: r\n", encoding="utf-8")
    return root


def test_migrate_objects_dry_run_does_not_move(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    result = run_migrate_objects(root, apply=False)
    assert result["dry_run"] is True
    assert result["planned"] == 6
    assert result["applied"] is False
    assert (root / "Configurations" / "platforms" / "sentinel.toml").is_file()
    assert not (root / ".opentide" / "configurations").exists()
    assert not (root / "objects" / "threats").exists()


def test_migrate_objects_apply_moves_layout(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    result = run_migrate_objects(root, apply=True)
    assert result["applied"] is True
    assert result["dry_run"] is False
    assert (root / ".opentide" / "configurations" / "platforms" / "sentinel.toml").is_file()
    assert not (root / "Configurations").exists()
    assert (root / ".opentide" / "schemas" / "rule.schema.json").is_file()
    assert (root / ".opentide" / "templates" / "rule.template.yaml").is_file()
    assert not (root / ".opentide" / "framework").exists()
    assert (root / "objects" / "threats" / "threat.yaml").is_file()
    assert (root / "objects" / "objectives" / "objective.yaml").is_file()
    assert (root / "objects" / "rules" / "rule.yaml").is_file()
    assert not (root / "Objects").exists()
    assert result["removed_empty"] == ["Objects", ".opentide/framework"]


def test_migrate_objects_copy_keeps_source(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    result = run_migrate_objects(root, apply=True, copy=True)
    assert result["copy"] is True
    assert (root / "Configurations" / "platforms" / "sentinel.toml").is_file()
    assert (root / ".opentide" / "configurations" / "platforms" / "sentinel.toml").is_file()
    assert (root / "Objects" / "Threat Vectors" / "threat.yaml").is_file()
    assert (root / "objects" / "threats" / "threat.yaml").is_file()
    assert "removed_empty" not in result


def test_migrate_objects_skips_existing_destination(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    dest = root / ".opentide" / "configurations" / "platforms"
    dest.mkdir(parents=True)
    (dest / "existing.toml").write_text("enabled = false\n", encoding="utf-8")
    result = run_migrate_objects(root, apply=True)
    skipped = [item for item in result["operations"] if item["from"] == "Configurations"]
    assert skipped[0]["action"] == "skip"
    assert skipped[0]["reason"] == "destination already exists"
    assert (root / "Configurations" / "platforms" / "sentinel.toml").is_file()
    assert (dest / "existing.toml").is_file()


def test_migrate_objects_idempotent_after_apply(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    run_migrate_objects(root, apply=True)
    second = run_migrate_objects(root, apply=True)
    assert second["planned"] == 0
    assert second["applied"] is False
    assert second["message"] == "No legacy layout paths to migrate"


def test_migrate_objects_skips_missing_sources(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()
    result = run_migrate_objects(root)
    assert result["planned"] == 0
    assert all(item["reason"] == "source missing" for item in result["operations"])


def test_migrate_objects_moves_models_library_and_global_toml_paths(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    library = root / "Models Library" / "Threat Vector Models"
    library.mkdir(parents=True)
    (library / "threat.yaml").write_text("name: t\n", encoding="utf-8")
    custom = root / "Catalogue" / "Rules"
    custom.mkdir(parents=True)
    (custom / "rule.yaml").write_text("name: r\n", encoding="utf-8")
    (root / "Configurations").mkdir()
    (root / "Configurations" / "global.toml").write_text(
        '[paths.tide]\nrule = "Catalogue/Rules"\n',
        encoding="utf-8",
    )
    result = run_migrate_objects(root, apply=True)
    assert result["applied"] is True
    assert (root / "objects" / "threats" / "threat.yaml").is_file()
    assert (root / "objects" / "rules" / "rule.yaml").is_file()
    assert not library.exists()


def test_migrate_objects_merges_client_and_models_library(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    library = root / "Models Library" / "Threat Vector Models"
    library.mkdir(parents=True)
    (library / "shared-threat.yaml").write_text("name: shared\n", encoding="utf-8")
    (root / "Models Library" / "Detection Objectives").mkdir(parents=True)
    (root / "Models Library" / "Detection Objectives" / "shared-objective.yaml").write_text(
        "name: shared-o\n", encoding="utf-8"
    )
    (root / "Models Library" / "Managed Detection Rules").mkdir(parents=True)
    (root / "Models Library" / "Managed Detection Rules" / "shared-rule.yaml").write_text(
        "name: shared-r\n", encoding="utf-8"
    )
    result = run_migrate_objects(root, apply=True)
    assert (root / "objects" / "threats" / "threat.yaml").is_file()
    assert (root / "objects" / "threats" / "shared-threat.yaml").is_file()
    assert not (root / "objects" / "threats" / "Threat Vector Models").exists()
    assert (root / "objects" / "objectives" / "objective.yaml").is_file()
    assert (root / "objects" / "objectives" / "shared-objective.yaml").is_file()
    assert (root / "objects" / "rules" / "rule.yaml").is_file()
    assert (root / "objects" / "rules" / "shared-rule.yaml").is_file()
    assert not (root / "Objects").exists()
    assert not (root / "Models Library").exists()
    assert result["removed_empty"] == ["Objects", "Models Library", ".opentide/framework"]


def test_migrate_objects_merge_keeps_the_first_file_on_collision(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    (root / "Objects" / "Threat Vectors").mkdir(parents=True)
    (root / "Objects" / "Threat Vectors" / "threat.yaml").write_text("client\n", encoding="utf-8")
    library = root / "Models Library" / "Threat Vector Models"
    library.mkdir(parents=True)
    (library / "threat.yaml").write_text("library\n", encoding="utf-8")
    run_migrate_objects(root, apply=True)
    assert (root / "objects" / "threats" / "threat.yaml").read_text(encoding="utf-8") == "client\n"
    assert not (root / "objects" / "threats" / "Threat Vector Models").exists()
    assert (library / "threat.yaml").is_file()


def test_migrate_objects_copy_merges_second_tree(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    library = root / "Models Library" / "Threat Vector Models"
    library.mkdir(parents=True)
    (library / "shared-threat.yaml").write_text("name: shared\n", encoding="utf-8")
    result = run_migrate_objects(root, apply=True, copy=True)
    assert result["copy"] is True
    assert (root / "objects" / "threats" / "threat.yaml").is_file()
    assert (root / "objects" / "threats" / "shared-threat.yaml").is_file()
    assert (library / "shared-threat.yaml").is_file()
    assert not (root / "objects" / "threats" / "Threat Vector Models").exists()


def test_migrate_objects_merges_nested_directories(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    (root / "Objects" / "Threat Vectors" / "group").mkdir(parents=True)
    (root / "Objects" / "Threat Vectors" / "group" / "a.yaml").write_text("a\n", encoding="utf-8")
    library = root / "Models Library" / "Threat Vector Models"
    (library / "group").mkdir(parents=True)
    (library / "group" / "b.yaml").write_text("b\n", encoding="utf-8")
    (library / "extra").mkdir()
    (library / "extra" / "c.yaml").write_text("c\n", encoding="utf-8")
    run_migrate_objects(root, apply=True)
    assert (root / "objects" / "threats" / "group" / "a.yaml").read_text(encoding="utf-8") == "a\n"
    assert (root / "objects" / "threats" / "group" / "b.yaml").read_text(encoding="utf-8") == "b\n"
    assert (root / "objects" / "threats" / "extra" / "c.yaml").is_file()
    assert not (root / "objects" / "threats" / "Threat Vector Models").exists()
    assert not library.exists()


def test_migrate_objects_copy_merges_a_new_directory(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    (root / "Objects" / "Threat Vectors").mkdir(parents=True)
    (root / "Objects" / "Threat Vectors" / "a.yaml").write_text("a\n", encoding="utf-8")
    extra = root / "Models Library" / "Threat Vector Models" / "extra"
    extra.mkdir(parents=True)
    (extra / "c.yaml").write_text("c\n", encoding="utf-8")
    run_migrate_objects(root, apply=True, copy=True)
    assert (root / "objects" / "threats" / "a.yaml").is_file()
    assert (root / "objects" / "threats" / "extra" / "c.yaml").is_file()
    assert (extra / "c.yaml").is_file()


def test_migrate_objects_cli_dry_run(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    result = runner.invoke(
        app,
        ["--json", "--repo", str(root), "migrate", "objects"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert '"dry_run": true' in result.stdout
    assert (root / "Configurations").is_dir()


def test_migrate_objects_cli_apply(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    result = runner.invoke(
        app,
        ["--json", "--repo", str(root), "migrate", "objects", "--apply"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert '"applied": true' in result.stdout
    assert (root / "objects" / "rules" / "rule.yaml").is_file()


def test_migrate_help_lists_objects() -> None:
    result = runner.invoke(app, ["migrate", "--help"])
    assert result.exit_code == 0
    assert "objects" in result.stdout
