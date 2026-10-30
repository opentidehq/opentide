"""``visibility.toml`` log sources name the datasets they fill, per ``system`` (#695)."""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from pydantic import ValidationError

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from opentide.models.visibility import (
    DATASET_FIELD_NAMES,
    DATASET_FIELDS,
    VisibilityConfig,
    VisibilityLogSource,
)
from opentide.validation.configuration import configuration_file_issues

#: Every system the dataset fields know, and one they do not.
SYSTEMS = (*DATASET_FIELDS, "crowdstrike")


def _value(field: str) -> object:
    return True if field == "ecs" else ["name-*"]


def _source(system: str | None, **fields: object) -> dict[str, Any]:
    return {"name": "logs", "description": "d", "system": system, **fields}


@pytest.mark.parametrize(
    ("system", "field"),
    [(system, field) for system, fields in DATASET_FIELDS.items() for field in fields],
)
def test_each_field_fits_its_system(system: str, field: str) -> None:
    source = VisibilityLogSource.model_validate(_source(system, **{field: _value(field)}))
    assert getattr(source, field) == _value(field)


@pytest.mark.parametrize(
    ("system", "field"),
    [
        (system, field)
        for system in SYSTEMS
        for field in DATASET_FIELD_NAMES
        if field not in DATASET_FIELDS.get(system, ())
    ],
)
def test_a_field_of_another_system_is_an_error(system: str, field: str) -> None:
    """A Splunk index can never make a Sentinel table known."""
    with pytest.raises(ValidationError) as raised:
        VisibilityLogSource.model_validate(_source(system, **{field: _value(field)}))
    [error] = raised.value.errors()
    assert error["loc"] == (field,)
    assert f"`{field}` does not apply to system {system!r}" in error["msg"]


def test_ecs_false_on_another_system_is_an_error_too() -> None:
    with pytest.raises(ValidationError, match="`ecs` does not apply to system 'splunk'"):
        VisibilityLogSource.model_validate(_source("splunk", ecs=False))


def test_an_empty_name_is_an_error() -> None:
    with pytest.raises(ValidationError, match="`tables` holds an empty name"):
        VisibilityLogSource.model_validate(_source("sentinel", tables=["SecurityEvent", "  "]))


def test_the_system_error_is_the_one_reported_when_system_is_wrong() -> None:
    with pytest.raises(ValidationError) as raised:
        VisibilityLogSource.model_validate(_source(None, tables=["T"]))
    assert [error["loc"] for error in raised.value.errors()] == [("system",)]


def test_configuration_check_reports_the_field_that_does_not_fit() -> None:
    issues = configuration_file_issues(
        "visibility.toml",
        {"logsources": [_source("splunk", indexes=["main"], tables=["SecurityEvent"])]},
    )
    assert [(issue.code, issue.field_path) for issue in issues] == [
        ("schema_validation", ("logsources", "0", "tables"))
    ]
    assert "applies to a log source of sentinel, defender_for_endpoint" in issues[0].message


# What the engine declares from the same text: it reads visibility.toml itself.


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


def test_no_dataset_fields_declare_nothing(declared: Callable[[str, str, str], str]) -> None:
    _install('[[logsources]]\nname = "l"\ndescription = "d"\nsystem = "splunk"\n')
    assert declared("splunk", "indexes", "main") == "unchecked"


DECLARING = """\
[[logsources]]
name = "a"
description = "d"
system = "sentinel"
tables = ["NTANetAnalytics", "*_CL", " AzureActivity "]

[[logsources]]
name = "b"
description = "d"
system = "splunk"
indexes = ["wineventlog"]
sourcetypes = []

[[logsources]]
name = "c"
description = "d"
system = "elastic"
indices = ["custom-ecs-*"]
ecs = true

[[logsources]]
name = "e"
description = "d"
system = "elastic"
indices = ["legacy-*"]
"""


def test_the_engine_declares_by_system_and_kind(declared: Callable[[str, str, str], str]) -> None:
    _install(DECLARING)
    assert declared("sentinel", "tables", "Custom_CL") == "declared"
    assert declared("sentinel", "tables", "AzureActivity") == "declared"  # trimmed
    assert declared("sentinel", "tables", "Other") == "undeclared"
    # Per system: a Sentinel table declares nothing for Defender.
    assert declared("defender_for_endpoint", "tables", "NTANetAnalytics") == "unchecked"
    assert declared("splunk", "indexes", "main") == "undeclared"
    # Opt-in per kind: an empty list declares none.
    assert declared("splunk", "sourcetypes", "anything") == "unchecked"
    # `ecs = true` marks only its own log source's indices.
    assert declared("elastic", "ecs_indices", "custom-ecs-1") == "declared"
    assert declared("elastic", "ecs_indices", "legacy-1") == "undeclared"
    assert declared("elastic", "indices", "legacy-1") == "declared"


def _scaffold() -> str:
    from opentide.core.root import get_data_root

    path = get_data_root() / "configurations" / "visibility.toml"
    return path.read_text(encoding="utf-8")


def test_the_scaffold_declares_nothing(declared: Callable[[str, str, str], str]) -> None:
    """The bundled file is every workspace's default: its examples stay commented out."""
    VisibilityConfig.model_validate(tomllib.loads(_scaffold()))
    _install(_scaffold())
    assert declared("splunk", "indexes", "main") == "unchecked"


def test_the_scaffold_examples_are_valid_one_per_platform(
    declared: Callable[[str, str, str], str],
) -> None:
    lines = _scaffold().splitlines()
    start = next(index for index, line in enumerate(lines) if line == "# [[logsources]]")
    example = "\n".join(line.removeprefix("#").removeprefix(" ") for line in lines[start:])
    VisibilityConfig.model_validate(tomllib.loads(example))
    _install(example)
    for platform, kind in (
        ("sentinel", "tables"),
        ("splunk", "indexes"),
        ("splunk", "sourcetypes"),
        ("splunk", "macros"),
        ("elastic", "indices"),
        ("elastic", "data_views"),
        ("elastic", "ecs_indices"),
    ):
        assert declared(platform, kind, "not-an-example") == "undeclared", (platform, kind)
