"""Bundled schema data paths."""

from __future__ import annotations

from opentide.schemas.store import generated_schemas_path, schemas_data_root


def test_schemas_data_root_exists() -> None:
    root = schemas_data_root()
    assert root.is_dir()


def test_generated_schemas_path_points_to_data_root() -> None:
    assert generated_schemas_path() == schemas_data_root()


def test_bundled_path_helpers_exist() -> None:
    from opentide.schemas.store import (
        bundled_data_exists,
        external_root,
        platform_configs_root,
        vocabulary_root,
    )

    assert vocabulary_root().name == "vocabulary"
    assert external_root().name == "external"
    assert platform_configs_root().parts[-2:] == ("configurations", "platforms")
    assert isinstance(bundled_data_exists(), bool)
