"""``visibility.toml`` log sources name the datasets they fill, per ``system`` (#695)."""

from __future__ import annotations

import sys
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


def test_no_dataset_fields_declare_nothing() -> None:
    config = VisibilityConfig.model_validate({"logsources": [_source("splunk")]})
    assert config.declared_datasets() == {}


def test_declared_datasets_by_system_and_kind() -> None:
    config = VisibilityConfig.model_validate(
        {
            "logsources": [
                _source("sentinel", tables=["NTANetAnalytics", "*_CL", " NTANetAnalytics "]),
                _source("sentinel", tables=["AzureActivity", "*_CL"]),
                _source("defender_for_endpoint", tables=["DeviceProcessEvents"]),
                _source(
                    "splunk",
                    indexes=["wineventlog"],
                    sourcetypes=[],
                    macros=["wineventlog_security"],
                ),
                _source(
                    "elastic",
                    indices=["custom-ecs-*", "logs-*"],
                    data_views=["security-solution-default"],
                    ecs=True,
                ),
                _source("elastic", indices=["legacy-*"], ecs=False),
                _source("elastic", data_views=["only-a-view"], ecs=True),
                _source("crowdstrike"),
            ]
        }
    )
    datasets = config.declared_datasets()
    assert datasets == {
        "defender_for_endpoint": {"tables": ["DeviceProcessEvents"]},
        "elastic": {
            "indices": ["custom-ecs-*", "legacy-*", "logs-*"],
            "data_views": ["only-a-view", "security-solution-default"],
            "ecs_indices": ["custom-ecs-*", "logs-*"],
        },
        "sentinel": {"tables": ["*_CL", "AzureActivity", "NTANetAnalytics"]},
        "splunk": {"indexes": ["wineventlog"], "macros": ["wineventlog_security"]},
    }
    # Platforms sorted, kinds in the engine's order: the file is stable.
    assert list(datasets) == sorted(datasets)
    assert list(datasets["elastic"]) == ["indices", "data_views", "ecs_indices"]


def _scaffold() -> str:
    from opentide.core.root import get_data_root

    path = get_data_root() / "configurations" / "visibility.toml"
    return path.read_text(encoding="utf-8")


def test_the_scaffold_declares_nothing() -> None:
    """The bundled file is every workspace's default: its examples stay commented out."""
    config = VisibilityConfig.model_validate(tomllib.loads(_scaffold()))
    assert config.declared_datasets() == {}


def test_the_scaffold_examples_are_valid_one_per_platform() -> None:
    lines = _scaffold().splitlines()
    start = next(index for index, line in enumerate(lines) if line == "# [[logsources]]")
    example = "\n".join(line.removeprefix("#").removeprefix(" ") for line in lines[start:])
    config = VisibilityConfig.model_validate(tomllib.loads(example))
    assert set(config.declared_datasets()) == {"sentinel", "splunk", "elastic"}
    assert set(config.declared_datasets()["elastic"]) == {"indices", "data_views", "ecs_indices"}
