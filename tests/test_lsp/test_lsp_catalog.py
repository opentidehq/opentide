"""``opentide generate schemas`` writes the language server's catalogs (#332)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from opentide.analysis import engine, install_workspace_catalog, reset_catalog
from opentide.generation.lsp_catalog import (
    CATALOG_DIR,
    DEPRECATIONS_FILE,
    FIELDS_FILE,
    catalog_differences,
    catalog_texts,
    deprecations_catalog,
    fields_catalog,
    main,
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
    assert fields["generator"] == "opentide.generation.lsp_catalog"
    assert fields["ref_leaves"]["detection_model"] == "objective"
    # One set of rows per registered revision, keyed by schema id.
    revisions = ["objective::1.0", "rule::1.0", "rule::1.1", "threat::1.0"]
    assert sorted({item["schema"] for item in fields["fields"]}) == revisions
    assert list(fields["schemas"]) == revisions
    assert fields["schemas"]["rule::1.0"] == {"family": "rule", "closed": True}
    keys = {"schema", "path", "name", "title", "description", "type", "required", "markdown"}
    assert all(keys <= set(item) for item in fields["fields"])
    paths = [(item["schema"], item["path"]) for item in fields["fields"]]
    assert paths == sorted(paths)


def test_each_revision_has_its_own_fields(fields: dict) -> None:
    """``metadata.reviewed`` is a rule::1.1 field: a rule::1.0 object may not carry it."""
    assert _field(fields, "rule::1.1", "metadata.reviewed")
    with pytest.raises(StopIteration):
        _field(fields, "rule::1.0", "metadata.reviewed")
    for schema in ("rule::1.0", "rule::1.1"):
        assert _field(fields, schema, "description")["required"] is True
        assert _field(fields, schema, "metadata")["closed"] is True


def test_open_objects_are_not_closed(fields: dict) -> None:
    """A mapping of free keys (internal references) takes any key."""
    internal = _field(fields, "rule::1.1", "references.internal")
    assert "closed" not in internal


def test_vocabulary_fields_list_their_values(fields: dict) -> None:
    tlp = _field(fields, "rule::1.1", "metadata.tlp")
    assert {"clear", "green", "amber", "red"} <= set(tlp["enum"])
    # metadata.schema offers every revision of the family, newest last, in
    # every revision: changing it is how an object moves to another one.
    for revision in ("rule::1.0", "rule::1.1"):
        schema = _field(fields, revision, "metadata.schema")
        assert schema["enum"] == ["rule::1.0", "rule::1.1"]
        assert schema["const"] is None
    assert _field(fields, "threat::1.0", "metadata.schema")["const"] == "threat::1.0"
    assert _field(fields, "rule::1.1", "detection_model")["ref"] == "objective"


def test_the_deprecations_name_root_and_platform_fields() -> None:
    rows = {(row["schema"], row["path"]) for row in deprecations_catalog("1.2.3")["fields"]}
    assert ("rule", "meta") in rows
    assert ("rule", "configurations.splunk.advanced") in rows


@pytest.fixture
def bundled_catalog() -> Iterator[None]:
    yield
    reset_catalog()


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
    # opentide installs what it generates, the same catalog as the files.
    state = install_workspace_catalog(tmp_path)
    assert state.source == "opentide", state.problem
    assert engine().catalog_version() == opentide.__version__


def test_differences_ignore_the_labels_and_name_the_fields() -> None:
    expected = catalog_texts()
    relabelled = {
        name: text.replace('"opentide.generation.lsp_catalog"', '"elsewhere"')
        for name, text in expected.items()
    }
    assert catalog_differences(expected, dict(relabelled)) == []
    fields = json.loads(expected[FIELDS_FILE])
    fields["fields"] = [row for row in fields["fields"] if row["path"] != "metadata.reviewed"]
    changed = {FIELDS_FILE: json.dumps(fields), DEPRECATIONS_FILE: None}
    assert catalog_differences(expected, changed) == [
        (FIELDS_FILE, "1 new (rule::1.1 metadata.reviewed)"),
        (DEPRECATIONS_FILE, "missing"),
    ]
    assert catalog_differences(expected, {FIELDS_FILE: "{", DEPRECATIONS_FILE: "{}"})[0][
        1
    ].startswith("does not parse")


def test_the_module_writes_and_checks_a_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """How language-server generates the catalogs compiled into the engine."""
    out = tmp_path / "generated"
    assert main(["--out", str(out), "--check"]) == 1
    assert "fields.json: missing" in capsys.readouterr().err
    assert main(["--out", str(out)]) == 0
    assert (out / FIELDS_FILE).read_text(encoding="utf-8") == catalog_texts()[FIELDS_FILE]
    assert main(["--out", str(out), "--check"]) == 0
    assert "match opentide's models" in capsys.readouterr().out


def _object_models() -> set[type]:
    """Every model an object revision is built from, root and nested."""
    import types as builtin_types
    import typing
    from typing import get_args, get_origin

    from opentide.models.base import TideModel
    from opentide.models.object_types import CORE_OBJECT_TYPES
    from opentide.models.schema_registry import identifiers_for_families, resolve_model

    def models_in(annotation: object) -> list[type[TideModel]]:
        if isinstance(annotation, type) and issubclass(annotation, TideModel):
            return [annotation]
        if get_origin(annotation) in (builtin_types.UnionType, typing.Union, list, tuple, dict):
            return [model for arg in get_args(annotation) for model in models_in(arg)]
        if get_origin(annotation) is typing.Annotated:
            return models_in(get_args(annotation)[0])
        return []

    seen: set[type] = set()
    pending = [resolve_model(i) for i in identifiers_for_families(CORE_OBJECT_TYPES)]
    while pending:
        model = pending.pop()
        if model in seen:
            continue
        seen.add(model)
        for field in model.model_fields.values():
            pending.extend(models_in(field.annotation))
    return seen


def test_a_model_that_rewrites_keys_declares_them_for_the_language_server() -> None:
    """A before-validator can accept keys no schema lists; the catalog only knows
    them from ``__legacy_keys__``, so every such model must declare its keys,
    even as an empty mapping, or the language server rejects objects that
    validate."""
    undeclared = sorted(
        model.__name__
        for model in _object_models()
        if any(
            decorator.info.mode == "before"
            for decorator in model.__pydantic_decorators__.model_validators.values()
        )
        and "__legacy_keys__" not in vars(model)
    )
    assert undeclared == []


def test_legacy_keys_reach_the_catalog(fields: dict) -> None:
    assert fields["schemas"]["objective::1.0"]["legacy"] == {"composition": None}
    splunk = _field(fields, "rule::1.1", "configurations.splunk")
    assert splunk["legacy"]["search"] == "query"
    scheduling = _field(fields, "rule::1.1", "configurations.splunk.scheduling")
    assert scheduling["legacy"]["frequency"] == "schedule"


def test_required_is_what_validation_requires(fields: dict) -> None:
    """The schema marks a rule's configurations and response required for the
    templates; the model, which validation runs, does not. The language server
    follows validation and only recommends them."""
    for schema in ("rule::1.0", "rule::1.1"):
        for path in ("configurations", "response"):
            row = _field(fields, schema, path)
            assert (row["required"], row.get("recommended")) == (False, True), (schema, path)
        assert _field(fields, schema, "description")["required"] is True
        assert "recommended" not in _field(fields, schema, "description")
