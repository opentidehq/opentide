"""Bundled schema data paths."""

from __future__ import annotations

from opentide.schemas.store import definitions_path, metaschemas_path, schemas_data_root


def test_schemas_data_root_exists() -> None:
    root = schemas_data_root()
    assert root.is_dir()
    assert (root / "MDR Meta Schema.yaml").is_file()


def test_metaschemas_path_points_to_bundled_data() -> None:
    assert metaschemas_path().name == "data"
    assert definitions_path().is_dir()


def test_definitions_path_is_subdirectory() -> None:
    root = schemas_data_root()
    defs = definitions_path()
    assert defs.is_dir()
    assert root in defs.parents or defs.parent == root
