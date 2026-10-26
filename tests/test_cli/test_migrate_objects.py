"""Tests for ``opentide migrate objects``."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services import migrate_objects
from opentide.cli.services.migrate_objects import _fix_destination_case, run_migrate_objects

runner = CliRunner()
#: The assertions read the human output; keep it on one line and uncoloured
#: whatever the host terminal is (CI runners report 80 columns).
_PLAIN_TERMINAL = {"COLUMNS": "1000", "NO_COLOR": "1", "FORCE_COLOR": None}


def _case_insensitive(directory: Path) -> bool:
    """Whether *directory* sits on a case-insensitive filesystem (macOS, Windows)."""
    probe = directory / "CaseProbe"
    probe.mkdir()
    try:
        return (directory / "caseprobe").exists()
    finally:
        probe.rmdir()


def _alias_objects(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``objects`` find ``Objects`` as on a case-insensitive filesystem.

    A symlink that ``os.listdir`` hides stands in for the case-insensitive lookup.
    """
    try:
        (root / "objects").symlink_to("Objects", target_is_directory=True)
    except OSError:
        pytest.skip("cannot create symlinks here")
    listdir = os.listdir
    monkeypatch.setattr(
        os,
        "listdir",
        lambda path: [name for name in listdir(path) if not Path(path, name).is_symlink()],
    )


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
    assert result["message"] == "Would move 6 folders · pass --apply to migrate"
    assert result["applied"] is False
    assert (root / "Configurations" / "platforms" / "sentinel.toml").is_file()
    assert not (root / ".opentide" / "configurations").exists()
    assert not (root / "objects" / "threats").exists()


def test_migrate_objects_apply_moves_layout(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    result = run_migrate_objects(root, apply=True)
    assert result["applied"] is True
    assert result["message"] == "Moved 6 folders"
    assert result["dry_run"] is False
    assert (root / ".opentide" / "configurations" / "platforms" / "sentinel.toml").is_file()
    assert not (root / "Configurations").exists()
    assert (root / ".opentide" / "schemas" / "rule.schema.json").is_file()
    assert (root / ".opentide" / "templates" / "rule.template.yaml").is_file()
    assert not (root / ".opentide" / "framework").exists()
    assert (root / "objects" / "threats" / "threat.yaml").is_file()
    assert (root / "objects" / "objectives" / "objective.yaml").is_file()
    assert (root / "objects" / "rules" / "rule.yaml").is_file()
    # Exact names: on a case-insensitive filesystem ``Objects`` also finds ``objects``.
    assert "objects" in os.listdir(root)
    assert "Objects" not in os.listdir(root)
    if _case_insensitive(tmp_path):
        assert result["case_renamed"] == [{"from": "Objects", "to": "objects"}]
        assert result["removed_empty"] == [".opentide/framework"]
    else:
        assert "case_renamed" not in result
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


def test_migrate_objects_cli_warns_about_a_configurations_folder_it_left(tmp_path: Path) -> None:
    """``setup platforms`` before the migration created ``.opentide/configurations``.

    The migration then skipped ``Configurations/`` and printed only
    ``OK Migrated 1 legacy path(s)``: the skip was visible in ``--json`` alone.
    """
    root = tmp_path / "legacy"
    (root / "Configurations" / "systems").mkdir(parents=True)
    (root / "Configurations" / "systems" / "sentinel.toml").write_text("x = 1\n", encoding="utf-8")
    (root / "Objects" / "Detection Rules").mkdir(parents=True)
    (root / "Objects" / "Detection Rules" / "r.yaml").write_text("name: r\n", encoding="utf-8")
    (root / ".opentide" / "configurations" / "platforms").mkdir(parents=True)
    (root / ".opentide" / "configurations" / "platforms" / "sentinel.toml").write_text(
        "enabled = true\n", encoding="utf-8"
    )

    dry = runner.invoke(app, ["--repo", str(root), "migrate", "objects"], env=_PLAIN_TERMINAL)
    applied = runner.invoke(
        app, ["--repo", str(root), "migrate", "objects", "--apply"], env=_PLAIN_TERMINAL
    )

    assert dry.exit_code == 0, dry.output
    assert "Left Configurations/ in place" in " ".join(dry.output.split())
    assert applied.exit_code == 1, applied.output
    output = " ".join(applied.output.split())
    assert "! Moved 1 folder; 1 legacy path(s) left in place" in output
    assert "Left Configurations/ in place: .opentide/configurations/ already exists" in output
    assert (root / "objects" / "rules" / "r.yaml").is_file()
    assert (root / "Configurations" / "systems" / "sentinel.toml").is_file()


def test_migrate_objects_warns_about_files_a_merge_left_behind(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    (root / "Objects" / "Threat Vectors").mkdir(parents=True)
    (root / "Objects" / "Threat Vectors" / "threat.yaml").write_text("client\n", encoding="utf-8")
    library = root / "Models Library" / "Threat Vector Models"
    library.mkdir(parents=True)
    (library / "threat.yaml").write_text("library\n", encoding="utf-8")
    (root / "objects" / "threats").mkdir(parents=True)
    (root / "objects" / "threats" / "threat.yaml").write_text("current\n", encoding="utf-8")
    expected = [
        f"{source}/threat.yaml was not moved: its destination already has a file or "
        "folder of that name."
        for source in ("Objects/Threat Vectors", "Models Library/Threat Vector Models")
    ]

    planned = run_migrate_objects(root)
    result = run_migrate_objects(root, apply=True)

    assert planned["warnings"] == expected
    assert "_exit_code" not in planned
    assert result["warnings"] == expected
    assert result["status"] == "issues"
    assert result["_exit_code"] == 1
    assert (root / "objects" / "threats" / "threat.yaml").read_text(encoding="utf-8") == (
        "current\n"
    )


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
    assert "objects" in os.listdir(root)
    assert "Objects" not in os.listdir(root)
    assert not (root / "Models Library").exists()
    if _case_insensitive(tmp_path):
        assert result["removed_empty"] == ["Models Library", ".opentide/framework"]
    else:
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


def test_migrate_objects_merges_leftover_models_library_into_existing_objects(
    tmp_path: Path,
) -> None:
    """A populated objects/ tree still absorbs a leftover Models Library."""
    root = tmp_path / "repo"
    threats = root / "objects" / "threats"
    threats.mkdir(parents=True)
    (threats / "threat.yaml").write_text("name: t\n", encoding="utf-8")
    library = root / "Models Library" / "Threat Vector Models"
    library.mkdir(parents=True)
    (library / "shared-threat.yaml").write_text("name: shared\n", encoding="utf-8")

    planned = run_migrate_objects(root, apply=False)
    library_ops = [
        item
        for item in planned["operations"]
        if item["from"] == "Models Library/Threat Vector Models"
    ]
    assert library_ops[0]["action"] == "move"
    assert (library / "shared-threat.yaml").is_file()

    applied = run_migrate_objects(root, apply=True)
    assert applied["applied"] is True
    assert (threats / "threat.yaml").read_text(encoding="utf-8") == "name: t\n"
    assert (threats / "shared-threat.yaml").read_text(encoding="utf-8") == "name: shared\n"
    assert not (threats / "Threat Vector Models").exists()
    assert not (root / "Models Library").exists()


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


def test_migrate_objects_renames_legacy_folder_on_case_insensitive_filesystem(
    tmp_path: Path,
) -> None:
    """``Objects`` and ``objects`` are one folder; the migrated tree must end up as ``objects``."""
    if not _case_insensitive(tmp_path):
        pytest.skip("needs a case-insensitive filesystem (macOS, Windows)")
    root = _legacy_repo(tmp_path)
    (root / "Objects" / "README.md").write_text("legacy\n", encoding="utf-8")

    planned = run_migrate_objects(root, apply=False)
    assert planned["case_renamed"] == [{"from": "Objects", "to": "objects"}]
    assert "advice" not in planned
    assert "Objects" in os.listdir(root)

    result = run_migrate_objects(root, apply=True)
    assert result["case_renamed"] == [{"from": "Objects", "to": "objects"}]
    assert "git rm -r --cached -q Objects" in str(result["advice"])
    assert "objects" in os.listdir(root)
    assert "Objects" not in os.listdir(root)
    assert sorted(os.listdir(root / "objects")) == ["README.md", "objectives", "rules", "threats"]
    assert not any(name.endswith(".opentide-case-rename") for name in os.listdir(root))


def test_case_fix_renames_through_a_temporary_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if _case_insensitive(tmp_path):
        pytest.skip(
            "simulates case-insensitivity with a symlink, "
            "which a real case-insensitive filesystem cannot host"
        )
    root = tmp_path / "repo"
    (root / "Objects" / "threats").mkdir(parents=True)
    _alias_objects(root, monkeypatch)
    destinations = ["objects/threats", "objects/rules"]

    assert _fix_destination_case(root, destinations, apply=False) == (
        [{"from": "Objects", "to": "objects"}],
        [],
    )

    renames: list[tuple[str, str]] = []
    monkeypatch.setattr(
        Path, "rename", lambda self, target: renames.append((self.name, Path(target).name))
    )
    assert _fix_destination_case(root, destinations, apply=True) == (
        [{"from": "Objects", "to": "objects"}],
        [],
    )
    assert renames == [
        ("Objects", "Objects.opentide-case-rename"),
        ("Objects.opentide-case-rename", "objects"),
    ]


def test_migrate_objects_lists_the_case_fix_and_advises_only_after_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runs on any filesystem: the case-variant lookup and the renames are patched."""
    root = _legacy_repo(tmp_path)
    monkeypatch.setattr(
        migrate_objects,
        "_case_variant",
        lambda parent, name: "Objects" if name == "objects" else None,
    )
    renames: list[tuple[str, str]] = []
    monkeypatch.setattr(
        Path, "rename", lambda self, target: renames.append((self.name, Path(target).name))
    )

    planned = run_migrate_objects(root, apply=False)
    assert planned["case_renamed"] == [{"from": "Objects", "to": "objects"}]
    assert "advice" not in planned
    assert renames == []

    result = run_migrate_objects(root, apply=True)
    assert result["case_renamed"] == [{"from": "Objects", "to": "objects"}]
    assert "git rm -r --cached -q Objects` then `git add objects`" in str(result["advice"])
    assert renames == [
        ("Objects", "Objects.opentide-case-rename"),
        ("Objects.opentide-case-rename", "objects"),
    ]


def test_migrate_objects_warns_once_when_the_case_rename_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A leftover temporary name keeps ``Objects``; ``--json`` readers see why."""
    if _case_insensitive(tmp_path):
        pytest.skip(
            "simulates case-insensitivity with a symlink, "
            "which a real case-insensitive filesystem cannot host"
        )
    root = _legacy_repo(tmp_path)
    _alias_objects(root, monkeypatch)
    (root / "Objects.opentide-case-rename").mkdir()
    # Recorded at the logger: loggers cached on first use bypass capture_logs.
    blocked: list[dict[str, object]] = []
    monkeypatch.setattr(
        migrate_objects,
        "logger",
        SimpleNamespace(
            debug=lambda event, **fields: None,
            warning=lambda event, **fields: blocked.append({"event": event, **fields}),
        ),
    )
    warning = (
        "Left Objects as it is instead of renaming it to objects: "
        "Objects.opentide-case-rename is in the way. "
        "Move anything you still need out of it, delete it, "
        "and run `opentide migrate objects --apply` again"
    )
    staged = str(root.resolve() / "Objects.opentide-case-rename")

    planned = run_migrate_objects(root, apply=False)
    assert "case_renamed" not in planned
    assert planned["warnings"] == [warning]
    assert blocked == [{"event": "migrate_case_rename_blocked", "path": staged}]

    blocked.clear()
    result = run_migrate_objects(root, apply=True)
    assert "case_renamed" not in result
    assert "advice" not in result
    assert result["warnings"] == [warning]
    assert blocked == [{"event": "migrate_case_rename_blocked", "path": staged}]
    assert (root / "Objects" / "threats" / "threat.yaml").is_file()
    assert "Objects" in os.listdir(root)


def test_migrate_objects_repairs_a_layout_an_earlier_release_migrated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No legacy source is left, but the migrated folders still sit in ``Objects``."""
    if _case_insensitive(tmp_path):
        pytest.skip(
            "simulates case-insensitivity with a symlink, "
            "which a real case-insensitive filesystem cannot host"
        )
    root = tmp_path / "repo"
    (root / "Objects" / "threats").mkdir(parents=True)
    (root / "Objects" / "threats" / "threat.yaml").write_text("name: t\n", encoding="utf-8")
    (root / "Objects" / "rules").mkdir()
    _alias_objects(root, monkeypatch)
    renames: list[tuple[str, str]] = []
    monkeypatch.setattr(
        Path, "rename", lambda self, target: renames.append((self.name, Path(target).name))
    )

    planned = run_migrate_objects(root, apply=False)
    assert planned["planned"] == 0
    assert planned["case_renamed"] == [{"from": "Objects", "to": "objects"}]
    assert planned["message"] == (
        "Would rename 1 folder to the exact case · pass --apply to rename"
    )
    assert planned["applied"] is False
    assert renames == []

    result = run_migrate_objects(root, apply=True)
    assert result["case_renamed"] == [{"from": "Objects", "to": "objects"}]
    assert result["message"] == "Renamed 1 folder to the exact case"
    assert result["applied"] is True
    assert "git rm -r --cached -q Objects` then `git add objects`" in str(result["advice"])
    assert renames == [
        ("Objects", "Objects.opentide-case-rename"),
        ("Objects.opentide-case-rename", "objects"),
    ]


def test_case_fix_leaves_a_case_sensitive_layout_alone(tmp_path: Path) -> None:
    if _case_insensitive(tmp_path):
        pytest.skip("Objects and objects cannot both exist on this filesystem")
    root = tmp_path / "repo"
    (root / "Objects" / "Other").mkdir(parents=True)
    (root / "objects" / "threats").mkdir(parents=True)
    assert _fix_destination_case(root, ["objects/threats"], apply=True) == ([], [])
    assert sorted(os.listdir(root)) == ["Objects", "objects"]


def test_migrate_objects_cli_dry_run(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    result = runner.invoke(
        app,
        ["--json", "--repo", str(root), "migrate", "objects"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["dry_run"] is True
    assert (root / "Configurations").is_dir()


def test_migrate_objects_cli_apply(tmp_path: Path) -> None:
    root = _legacy_repo(tmp_path)
    result = runner.invoke(
        app,
        ["--json", "--repo", str(root), "migrate", "objects", "--apply"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["applied"] is True
    assert (root / "objects" / "rules" / "rule.yaml").is_file()


def test_migrate_help_lists_objects() -> None:
    result = runner.invoke(app, ["migrate", "--help"])
    assert result.exit_code == 0
    assert "objects" in result.stdout
