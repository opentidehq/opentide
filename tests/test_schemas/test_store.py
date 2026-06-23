"""Bundled schema data paths."""

from __future__ import annotations

from opentide.schemas.store import generated_schemas_path, schemas_data_root


def test_schemas_data_root_exists() -> None:
    root = schemas_data_root()
    assert root.is_dir()


def test_generated_schemas_path_points_to_data_root() -> None:
    assert generated_schemas_path() == schemas_data_root()
