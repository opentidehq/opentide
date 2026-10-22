"""The catalogue is the direct ``*.yaml``/``*.yml`` children of a family folder (#584)."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.registry.catalogue import (
    NESTED_INDEX_KEY,
    catalogue_files,
    is_object_file_name,
    nested_file_message,
    nested_files_message,
    report_nested_object_files,
    scan_object_dir,
    with_nested_object_warning,
)


def _touch(root: Path, *relatives: str) -> None:
    for relative in relatives:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("name: x\n", encoding="utf-8")


def test_scan_splits_direct_children_from_nested_files(tmp_path: Path) -> None:
    _touch(
        tmp_path,
        "a.yaml",
        "b.yml",
        "c.YAML",
        "notes.txt",
        "scratch.debug.yaml",
        "team/x.yaml",
        "team/deep/y.yml",
        "team/z.debug.yaml",
    )
    (tmp_path / "folder.yaml").mkdir()

    scan = scan_object_dir(tmp_path)

    assert [path.name for path in scan.files] == ["a.yaml", "b.yml"]
    assert [path.relative_to(tmp_path).as_posix() for path in scan.nested] == [
        "team/deep/y.yml",
        "team/x.yaml",
    ]
    assert catalogue_files(tmp_path) == list(scan.files)
    with_debug = catalogue_files(tmp_path, include_debug=True)
    assert tmp_path / "scratch.debug.yaml" in with_debug


def test_scan_of_a_missing_folder_is_empty(tmp_path: Path) -> None:
    scan = scan_object_dir(tmp_path / "absent")
    assert scan.files == ()
    assert scan.nested == ()


@pytest.mark.parametrize(
    ("name", "expected"),
    [("a.yaml", True), ("a.yml", True), ("a.json", False), ("a.debug.yaml", False)],
)
def test_object_file_names(name: str, expected: bool) -> None:
    assert is_object_file_name(name) is expected


def test_messages_name_every_path() -> None:
    one = nested_file_message("objects/rules/team/b.yaml", "objects/rules")
    assert one.startswith("objects/rules/team/b.yaml is in a subfolder of objects/rules")
    assert "not an object instance" in one
    many = nested_files_message(["objects/rules/team/b.yaml", "objects/threats/x/c.yaml"])
    assert many.startswith("2 object file(s) in subfolders")
    assert many.endswith("objects/rules/team/b.yaml, objects/threats/x/c.yaml")


def test_report_appends_once_or_logs(tmp_path: Path) -> None:
    index = {
        NESTED_INDEX_KEY: [
            {"path": str(tmp_path / "objects/rules/team/b.yaml"), "folder": "", "object_type": ""}
        ]
    }
    warnings: list[str] = []
    paths = report_nested_object_files(index, warnings=warnings)
    assert len(paths) == 1
    assert len(warnings) == 1
    assert paths[0] in warnings[0]
    assert report_nested_object_files({}, warnings=warnings) == []
    assert len(warnings) == 1
    assert report_nested_object_files(index) == paths


def test_payload_warning_keeps_existing_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.registry import catalogue

    monkeypatch.setattr(
        catalogue,
        "nested_entries",
        lambda index=None: [{"path": "/w/objects/rules/team/b.yaml"}],
    )
    payload = with_nested_object_warning({"message": "ok", "warnings": ["first"]})
    assert payload["warnings"][0] == "first"
    assert "/w/objects/rules/team/b.yaml" in payload["warnings"][1]

    monkeypatch.setattr(catalogue, "nested_entries", lambda index=None: [])
    assert with_nested_object_warning({"message": "ok"}) == {"message": "ok"}


@pytest.mark.parametrize("name", ["a.yaml", "a.yml", "a.YAML", "a.Yml", "a.YML", "a.json"])
def test_object_file_names_match_deploy_and_inflight(name: str) -> None:
    """``deploy`` and inflight shards match suffixes case-sensitively; so does the catalogue.

    Otherwise ``objects/rules/r.YAML`` is indexed, validated and shared by a full
    ``share push`` while ``deploy`` skips it without a warning (#584, #312).
    """
    from opentide.deployment.git_repo import RULE_SUFFIXES
    from opentide.indexing.inflight import _is_object_yaml

    deployed = Path(name).suffix in RULE_SUFFIXES
    assert is_object_file_name(name) is deployed
    assert _is_object_yaml(f"objects/rules/{name}") is deployed
