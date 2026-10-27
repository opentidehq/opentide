"""``opentide generate schemas`` writes the language server's catalogs (#332)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from opentide.analysis import engine, install_workspace_catalog
from opentide.generation.lsp_catalog import (
    CATALOG_DIR,
    DEPRECATIONS_FILE,
    FIELDS_FILE,
    deprecations_catalog,
    fields_catalog,
    write_catalog,
)


@pytest.fixture(scope="module")
def fields() -> dict:
    return fields_catalog("1.2.3")


def _field(catalog: dict, schema: str, path: str) -> dict:
    return next(
        item for item in catalog["fields"] if (item["schema"], item["path"]) == (schema, path)
    )


def test_the_field_catalog_has_the_engines_shape(fields: dict) -> None:
    assert fields["opentide"] == "1.2.3"
    assert fields["generator"] == "opentide generate schemas"
    assert fields["ref_leaves"]["detection_model"] == "objective"
    assert {item["schema"] for item in fields["fields"]} == {"rule", "threat", "objective"}
    keys = {"schema", "path", "name", "title", "description", "type", "required", "markdown"}
    assert all(keys <= set(item) for item in fields["fields"])
    paths = [(item["schema"], item["path"]) for item in fields["fields"]]
    assert paths == sorted(paths)


def test_vocabulary_fields_list_their_values(fields: dict) -> None:
    tlp = _field(fields, "rule", "metadata.tlp")
    assert {"clear", "green", "amber", "red"} <= set(tlp["enum"])
    # metadata.schema offers every revision of the family, newest last.
    schema = _field(fields, "rule", "metadata.schema")
    assert schema["enum"][0] == "rule::1.0" and len(schema["enum"]) >= 2
    assert schema["const"] is None
    assert _field(fields, "rule", "detection_model")["ref"] == "objective"


def test_the_deprecations_name_root_and_platform_fields() -> None:
    rows = {(row["schema"], row["path"]) for row in deprecations_catalog("1.2.3")["fields"]}
    assert ("rule", "meta") in rows
    assert ("rule", "configurations.splunk.advanced") in rows


@pytest.fixture
def bundled_catalog() -> Iterator[None]:
    yield
    install_workspace_catalog(None)


def test_the_written_catalogs_are_what_the_engine_installs(
    tmp_path: Path, bundled_catalog: None
) -> None:
    written = write_catalog(tmp_path)
    assert written == [
        tmp_path / CATALOG_DIR / FIELDS_FILE,
        tmp_path / CATALOG_DIR / DEPRECATIONS_FILE,
    ]
    import opentide

    assert json.loads(written[0].read_text(encoding="utf-8"))["opentide"] == opentide.__version__
    state = install_workspace_catalog(tmp_path)
    assert state.source == "workspace", state.problem
    assert engine().catalog_version() == opentide.__version__
