"""A ``visibility.toml`` log source is one dataset, named by ``name``, with its columns (#718).

The spec's conformance fixtures (``specifications/fixtures/visibility``) are
copied verbatim under ``tests/fixtures/specifications/visibility``.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from opentide.models.visibility import (
    COLUMN_TYPES,
    LEGACY_DATASET_KEYS,
    VisibilityConfig,
    VisibilityLogSource,
)
from opentide.validation.configuration import configuration_file_issues

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "specifications" / "visibility"

#: Engine tests that read the new shape: the pinned engine (language-server
#: 0.7.0) still reads the 0.20.0 plural lists. They flip when it is repinned.
NEEDS_ENGINE = pytest.mark.xfail(
    reason="needs language-server with visibility::1.0 singular datasets (language-server#146)",
    strict=True,
)


def _source(system: str = "sentinel", **fields: object) -> dict[str, Any]:
    return {"name": "Contoso_Audit_CL", "description": "d", "system": system, **fields}


def _issues(*sources: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    issues = configuration_file_issues("visibility.toml", {"logsources": list(sources)})
    return [(issue.code, issue.field_path) for issue in issues]


# --- Keys ----------------------------------------------------------------------------------


def test_a_log_source_takes_its_keys_and_nothing_else() -> None:
    source = VisibilityLogSource.model_validate(
        _source(tenants=["Production"], assets=["IdP"], references=["https://example.org"])
    )
    assert (source.name, source.columns) == ("Contoso_Audit_CL", None)
    assert _issues(_source(table="Contoso_Audit_CL")) == [
        ("unknown_key", ("logsources", "0", "table"))
    ]


@pytest.mark.parametrize("key", ["name", "description", "system"])
def test_name_description_and_system_are_required(key: str) -> None:
    source = _source()
    del source[key]
    assert _issues(source) == [("missing_field", ("logsources", "0", key))]


@pytest.mark.parametrize("name", ["", "  "])
def test_an_empty_name_is_an_error(name: str) -> None:
    assert _issues(_source(name=name)) == [("schema_validation", ("logsources", "0", "name"))]


@pytest.mark.parametrize("key", LEGACY_DATASET_KEYS)
def test_a_0_20_0_key_says_what_to_do_instead(key: str) -> None:
    value = True if key == "ecs" else ["A", "B"]
    issues = configuration_file_issues("visibility.toml", {"logsources": [_source(**{key: value})]})
    assert [(issue.code, issue.field_path) for issue in issues] == [
        ("schema_validation", ("logsources", "0", key))
    ]
    message = issues[0].message
    assert message.startswith(f"`{key}` ")
    if key in ("tables", "sourcetypes", "indices"):
        assert "its own [[logsources]] entry whose `name` is the" in message
    else:
        assert message.endswith("remove it")
    assert "migrate" not in message


def test_the_system_error_is_the_one_reported_when_system_is_wrong() -> None:
    with pytest.raises(ValidationError) as raised:
        VisibilityLogSource.model_validate(
            _source(system=None, columns={"A": {"type": "string"}})  # type: ignore[arg-type]
        )
    assert [error["loc"] for error in raised.value.errors()] == [("system",)]


def test_names_are_unique_per_system() -> None:
    assert _issues(_source(), _source(description="again")) == [
        ("schema_validation", ("logsources", "1", "name"))
    ]
    # The same name under two systems is fine.
    assert (
        _issues(_source(name="DeviceEvents"), _source("defender_for_endpoint", name="DeviceEvents"))
        == []
    )


# --- Columns -------------------------------------------------------------------------------


@pytest.mark.parametrize("system", sorted(COLUMN_TYPES))
def test_every_type_of_a_system_is_accepted(system: str) -> None:
    columns = {f"c{i}": {"type": kind} for i, kind in enumerate(COLUMN_TYPES[system])}
    source = VisibilityLogSource.model_validate(_source(system, columns=columns))
    assert [column.type for column in (source.columns or {}).values()] == list(COLUMN_TYPES[system])


@pytest.mark.parametrize(
    ("system", "kind"),
    [("sentinel", "keyword"), ("splunk", "datetime"), ("elastic", "string")],
)
def test_a_type_of_another_system_is_an_error_on_that_column(system: str, kind: str) -> None:
    columns = {"ok": {"type": COLUMN_TYPES[system][0]}, "process.name": {"type": kind}}
    assert _issues(_source(system, columns=columns)) == [
        ("schema_validation", ("logsources", "0", "columns", "process.name", "type"))
    ]


def test_columns_on_a_system_without_a_type_set_are_an_error() -> None:
    assert _issues(_source("crowdstrike", columns={"a": {"type": "string"}})) == [
        ("schema_validation", ("logsources", "0", "columns"))
    ]


def test_a_column_takes_a_type_and_a_description_only() -> None:
    source = VisibilityLogSource.model_validate(
        _source(columns={"Actor_s": {"type": "string", "description": "UPN"}})
    )
    assert source.columns is not None and source.columns["Actor_s"].description == "UPN"
    assert _issues(_source(columns={"Actor_s": {}})) == [
        ("missing_field", ("logsources", "0", "columns", "Actor_s", "type"))
    ]
    assert _issues(_source(columns={"Actor_s": {"type": "string", "nullable": True}})) == [
        ("unknown_key", ("logsources", "0", "columns", "Actor_s", "nullable"))
    ]
    assert _issues(_source(columns={"": {"type": "string"}})) == [
        ("schema_validation", ("logsources", "0", "columns", ""))
    ]


# --- The spec's conformance fixtures --------------------------------------------------------

#: The finding each invalid fixture raises, and where.
INVALID = {
    "column-bad-type.toml": (
        "schema_validation",
        ("logsources", "0", "columns", "Actor_s", "type"),
    ),
    "column-missing-type.toml": (
        "missing_field",
        ("logsources", "0", "columns", "Actor_s", "type"),
    ),
    "column-unknown-key.toml": (
        "unknown_key",
        ("logsources", "0", "columns", "Actor_s", "nullable"),
    ),
    "columns-not-a-table.toml": ("schema_validation", ("logsources", "0", "columns")),
    "columns-unsupported-system.toml": ("schema_validation", ("logsources", "0", "columns")),
    "duplicate-name.toml": ("schema_validation", ("logsources", "1", "name")),
    "ecs.toml": ("schema_validation", ("logsources", "0", "ecs")),
    "empty-name.toml": ("schema_validation", ("logsources", "0", "name")),
    "missing-description.toml": ("missing_field", ("logsources", "0", "description")),
    "missing-name.toml": ("missing_field", ("logsources", "0", "name")),
    "missing-system.toml": ("missing_field", ("logsources", "0", "system")),
    "plural-key.toml": ("schema_validation", ("logsources", "0", "tables")),
    "unknown-asset.toml": ("asset_unknown", ("logsources", "0", "assets", "0")),
    "unknown-key.toml": ("unknown_key", ("logsources", "0", "table")),
    "unknown-top-level.toml": ("unknown_key", ("datasets",)),
}


def _fixture(*parts: str) -> dict[str, Any]:
    return tomllib.loads(FIXTURES.joinpath(*parts).read_text(encoding="utf-8"))


def test_every_invalid_fixture_is_listed() -> None:
    assert sorted(path.name for path in (FIXTURES / "invalid").glob("*.toml")) == sorted(INVALID)


@pytest.mark.parametrize("name", sorted(INVALID))
def test_an_invalid_fixture_fails_with_its_code(name: str) -> None:
    issues = configuration_file_issues("visibility.toml", _fixture("invalid", name))
    assert [(issue.code, issue.field_path) for issue in issues] == [INVALID[name]]


def test_the_valid_fixture_validates() -> None:
    document = _fixture("valid", "visibility.toml")
    assert configuration_file_issues("visibility.toml", document) == []
    VisibilityConfig.model_validate(document)


# --- The bundled file -----------------------------------------------------------------------


def _scaffold() -> str:
    from opentide.core.root import get_data_root

    path = get_data_root() / "configurations" / "visibility.toml"
    return path.read_text(encoding="utf-8")


def _scaffold_examples() -> str:
    lines = _scaffold().splitlines()
    start = next(index for index, line in enumerate(lines) if line == "# [[logsources]]")
    return "\n".join(line.removeprefix("#").removeprefix(" ") for line in lines[start:])


def test_the_scaffold_declares_no_log_source() -> None:
    """The bundled file is every workspace's default: its examples stay commented out."""
    assert VisibilityConfig.model_validate(tomllib.loads(_scaffold())).logsources == []


def test_the_scaffold_examples_are_valid_one_per_platform_one_with_columns() -> None:
    config = VisibilityConfig.model_validate(tomllib.loads(_scaffold_examples()))
    assert {source.system for source in config.logsources} == {"sentinel", "splunk", "elastic"}
    assert any(source.columns for source in config.logsources)


# --- What the engine declares from the same text: it reads visibility.toml itself --------


@pytest.fixture
def declared() -> Iterator[Callable[[str, str, str], str]]:
    """``status(platform, kind, name)`` of the declarations installed by the test."""
    from opentide.analysis import engine

    module = engine()
    yield lambda platform, kind, name: module.dataset_status(platform, kind, name)
    module.install_visibility()


def _install(text: str) -> None:
    from opentide.analysis import engine

    engine().install_visibility(text)


def test_the_scaffold_declares_nothing_to_the_engine(
    declared: Callable[[str, str, str], str],
) -> None:
    _install(_scaffold())
    assert declared("splunk", "sourcetypes", "anything") == "unchecked"
    assert declared("sentinel", "tables", "Anything") == "unchecked"


DECLARING = """\
[[logsources]]
name = "NTANetAnalytics"
description = "d"
system = "sentinel"

[[logsources]]
name = "*_CL"
description = "d"
system = "sentinel"

[[logsources]]
name = "WinEventLog:Security"
description = "d"
system = "splunk"

[[logsources]]
name = "logs-endpoint.events.*"
description = "d"
system = "elastic"
"""


@NEEDS_ENGINE
def test_the_engine_declares_by_system(declared: Callable[[str, str, str], str]) -> None:
    _install(DECLARING)
    assert declared("sentinel", "tables", "Custom_CL") == "declared"
    assert declared("sentinel", "tables", "NTANetAnalytics") == "declared"
    assert declared("sentinel", "tables", "Other") == "undeclared"
    # Per system: a Sentinel table declares nothing for Defender.
    assert declared("defender_for_endpoint", "tables", "NTANetAnalytics") == "unchecked"
    # Splunk names are sourcetypes, matched regardless of case.
    assert declared("splunk", "sourcetypes", "wineventlog:security") == "declared"
    assert declared("splunk", "sourcetypes", "other") == "undeclared"
    assert declared("elastic", "indices", "logs-endpoint.events.process") == "declared"
    assert declared("elastic", "indices", "winlogbeat-*") == "undeclared"


@NEEDS_ENGINE
def test_the_engine_declares_the_scaffold_examples(
    declared: Callable[[str, str, str], str],
) -> None:
    _install(_scaffold_examples())
    for platform, kind in (
        ("sentinel", "tables"),
        ("splunk", "sourcetypes"),
        ("elastic", "indices"),
    ):
        assert declared(platform, kind, "not-an-example") == "undeclared", (platform, kind)
