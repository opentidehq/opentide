"""ExabeamConfig and its constraint codes (exabeam-1.0, Constraints)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from opentide.loading.platform_loader import load_platform_config
from opentide.models.platform import PLATFORM_CONFIG_MODELS, ExabeamConfig, RuleConfigurations
from opentide.platforms.exabeam.constraints import (
    CONSTRAINT_CODES,
    block_codes,
    block_findings,
    duration,
    uses_context_table,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "exabeam"
QUERY = 'activity_type:"app-login"'

#: The code each specification invalid fixture names in its header. The fifth,
#: rule-exabeam-advanced-query.yaml, is a language code: the engine's.
INVALID = {
    "rule-exabeam-correlation-single.yaml": "exabeam_correlation",
    "rule-exabeam-threshold-operator.yaml": "exabeam_threshold_operator",
    "rule-exabeam-context-table-threshold.yaml": "exabeam_context_table_trigger",
    "rule-exabeam-delay.yaml": "exabeam_duration",
}


def _block(**keys: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "enabled": True,
        "schema": "platform::exabeam::1.0",
        "status": "STAGING",
        "sequences": [{"query": QUERY}],
    }
    return {**base, **keys}


def _codes(**keys: Any) -> set[str]:
    return block_codes(_block(**keys))


def _threshold(**keys: Any) -> list[dict[str, Any]]:
    threshold = {"function": "count", "operator": "more_than", "value": 5, "within": "10m", **keys}
    return [{"query": QUERY, "threshold": {k: v for k, v in threshold.items() if v is not None}}]


def _errors(block: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    """``(code, field_path)`` for each finding, as validate reports them."""
    with pytest.raises(ValidationError) as caught:
        ExabeamConfig.model_validate(block)
    return [(error["type"], tuple(map(str, error["loc"]))) for error in caught.value.errors()]


def test_exabeam_is_a_registered_platform() -> None:
    assert PLATFORM_CONFIG_MODELS["exabeam"] is ExabeamConfig
    assert ExabeamConfig.schema_identifier() == "platform::exabeam::1.0"
    assert "exabeam" in RuleConfigurations.model_fields


@pytest.mark.parametrize(
    "name",
    ["block-exabeam.yaml", "rule-exabeam-threshold-1.0.yaml", "rule-exabeam-sequence-1.0.yaml"],
)
def test_the_specification_fixtures_validate(name: str) -> None:
    document = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    block = load_platform_config("exabeam", document["configurations"]["exabeam"])
    assert isinstance(block, ExabeamConfig)
    assert block_findings(document["configurations"]["exabeam"]) == []


@pytest.mark.parametrize(("name", "code"), sorted(INVALID.items()))
def test_each_invalid_fixture_fails_with_its_code(name: str, code: str) -> None:
    document = yaml.safe_load((FIXTURES / "invalid" / name).read_text(encoding="utf-8"))
    assert {found for found, _ in _errors(document["configurations"]["exabeam"])} == {code}


def test_the_advanced_query_fixture_is_the_engines() -> None:
    """``exabeam_advanced_in_rule`` is a language code: the block itself is well formed."""
    document = yaml.safe_load(
        (FIXTURES / "invalid" / "rule-exabeam-advanced-query.yaml").read_text(encoding="utf-8")
    )
    assert block_findings(document["configurations"]["exabeam"]) == []


# The cases of specifications/scripts/test_platform_exabeam.py (CheckerTests.test_block_codes),
# without the language and unknown-key ones, which are not this module's.
@pytest.mark.parametrize(
    ("keys", "codes"),
    [
        ({}, set()),
        ({"sequences": []}, {"exabeam_sequences"}),
        ({"sequences": [{"query": "  "}]}, {"exabeam_sequences"}),
        (
            {"sequences": [{"query": 'vendor:"a"'}, {"query": 'vendor:"b"'}]},
            {"exabeam_correlation"},
        ),
        (
            {
                "sequences": [{"query": 'vendor:"a"'}, {"query": 'vendor:"b"'}],
                "correlation": {"within": "15m"},
            },
            set(),
        ),
        (
            {
                "sequences": [{"query": 'vendor:"a"'}, {"query": 'vendor:"b"'}],
                "correlation": {"within": "1h30m"},
            },
            {"exabeam_duration"},
        ),
        ({"sequences": _threshold(function="median")}, {"exabeam_threshold_function"}),
        ({"sequences": _threshold(function="sum")}, {"exabeam_threshold_function"}),
        ({"sequences": _threshold(function="sum", field="bytes")}, set()),
        ({"sequences": _threshold(function="sum", field=" ")}, {"exabeam_threshold_function"}),
        (
            {"sequences": _threshold(function="value", field="dest_ip")},
            {"exabeam_threshold_operator"},
        ),
        (
            {
                "sequences": _threshold(
                    function="value", field="dest_ip", operator="not_in", value=["1.1.1.1"]
                )
            },
            set(),
        ),
        (
            {
                "sequences": _threshold(
                    function="value", field="user", operator="changed", value=None
                )
            },
            {"exabeam_threshold_operator"},
        ),
        ({"sequences": _threshold(value=2.5)}, {"exabeam_threshold_value"}),
        ({"sequences": _threshold(value=-1)}, {"exabeam_threshold_value"}),
        ({"sequences": _threshold(value=True)}, {"exabeam_threshold_value"}),
        ({"sequences": _threshold(function="max", field="bytes", value=2.5)}, set()),
        (
            {
                "sequences": _threshold(
                    function="value", field="dest_ip", operator="in", value=["a,b"]
                )
            },
            {"exabeam_threshold_value"},
        ),
        (
            {"sequences": _threshold(operator="between", value=[2, 10])},
            {"exabeam_threshold_operator"},
        ),
        ({"sequences": _threshold(within="1w")}, {"exabeam_duration"}),
        ({"sequences": [{"query": QUERY, "group_by": ["a", "b", "c", "d"]}]}, {"exabeam_group_by"}),
        ({"sequences": [{"query": QUERY, "group_by": ["a", "a"]}]}, {"exabeam_group_by"}),
        ({"sequences": [{"query": QUERY, "group_by": []}]}, {"exabeam_group_by"}),
        ({"severity": "High"}, {"exabeam_severity"}),
        ({"outcome": "webhook"}, {"exabeam_outcome"}),
        ({"email": {"recipients": []}}, {"exabeam_email"}),
        ({"email": {"recipients": ["soc"]}}, {"exabeam_email"}),
        ({"email": {"recipients": ["a@b.io", "a@b.io"]}}, {"exabeam_email"}),
        ({"email": {"recipients": ["soc@example.com"], "subject": " "}}, {"exabeam_email"}),
        ({"email": {"recipients": ["soc@example.com"], "subject": "x"}}, set()),
        ({"suppression": {"for": "2w", "group_by": ["user"]}}, set()),
        ({"suppression": {"for": "0m"}}, {"exabeam_duration"}),
        ({"suppression": {"for": "1h", "group_by": []}}, {"exabeam_group_by"}),
        ({"delay": "3h"}, set()),
        ({"delay": "7m"}, set()),
        ({"delay": "181m"}, {"exabeam_duration"}),
        ({"delay": "1d"}, {"exabeam_duration"}),
        (
            {"schedule": [{"every": "week", "days": ["monday"], "from": "08:00Z", "to": "18:00Z"}]},
            set(),
        ),
        (
            {"schedule": [{"every": "week", "days": ["mon"], "from": "08:00Z", "to": "18:00Z"}]},
            {"exabeam_schedule"},
        ),
        ({"schedule": [{"every": "day", "from": "8am", "to": "18:00Z"}]}, {"exabeam_schedule"}),
        (
            {"schedule": [{"every": "day", "from": "08:00Z", "to": "18:00Z", "days": [1]}]},
            {"exabeam_schedule"},
        ),
        (
            {"schedule": [{"every": "month", "from": "00:00Z", "to": "23:59Z", "last_day": True}]},
            set(),
        ),
        (
            {"schedule": [{"every": "month", "from": "00:00Z", "to": "23:59Z", "days": [0]}]},
            {"exabeam_schedule"},
        ),
        (
            {"schedule": [{"every": "month", "from": "00:00Z", "to": "23:59Z"}]},
            {"exabeam_schedule"},
        ),
        (
            {
                "schedule": [
                    {
                        "every": "days",
                        "first": "monday",
                        "last": "friday",
                        "from": "06:00Z",
                        "to": "20:00Z",
                    }
                ]
            },
            set(),
        ),
        ({"schedule": []}, {"exabeam_schedule"}),
        ({"name": "x" * 129}, {"exabeam_name_length"}),
        ({"name": "x" * 128}, set()),
    ],
)
def test_block_codes(keys: dict[str, Any], codes: set[str]) -> None:
    assert _codes(**keys) == codes


def test_each_code_is_reported_at_its_spec_path() -> None:
    block = _block(
        sequences=[
            {"query": " "},
            {"query": QUERY, "group_by": [], "threshold": {"function": "x", "within": "1h"}},
        ],
        severity="High",
        outcome="webhook",
        email={"recipients": []},
        suppression={"for": "1x", "group_by": []},
        delay="5m",
        schedule=[{"every": "hour", "from": "08:00Z", "to": "09:00Z"}],
        name="x" * 200,
    )
    assert sorted(_errors(block)) == sorted(
        [
            ("exabeam_sequences", ("sequences", "0", "query")),
            ("exabeam_group_by", ("sequences", "1", "group_by")),
            ("exabeam_threshold_function", ("sequences", "1", "threshold")),
            ("exabeam_correlation", ("correlation",)),
            ("exabeam_severity", ("severity",)),
            ("exabeam_outcome", ("outcome",)),
            ("exabeam_email", ("email",)),
            ("exabeam_duration", ("suppression", "for")),
            ("exabeam_group_by", ("suppression", "group_by")),
            ("exabeam_duration", ("delay",)),
            ("exabeam_schedule", ("schedule", "0")),
            ("exabeam_name_length", ("name",)),
        ]
    )
    assert {code for code, _ in _errors(block)} <= CONSTRAINT_CODES


def test_threshold_and_window_paths() -> None:
    block = _block(
        sequences=[
            {
                "query": 'user IN "Privileged Accounts"',
                "threshold": {
                    "function": "count",
                    "operator": "more_than",
                    "value": 1,
                    "within": "1w",
                },
            },
            {"query": QUERY},
        ],
        correlation={"within": "PT1H", "group_by": ["a", "a"]},
    )
    assert sorted(_errors(block)) == [
        ("exabeam_context_table_trigger", ("sequences", "0", "threshold")),
        ("exabeam_duration", ("correlation", "within")),
        ("exabeam_duration", ("sequences", "0", "threshold", "within")),
        ("exabeam_group_by", ("correlation", "group_by")),
    ]


def test_a_model_dump_validates_again() -> None:
    """A dump writes every optional key as null: each is read as the key left out."""
    document = yaml.safe_load(
        (FIXTURES / "rule-exabeam-sequence-1.0.yaml").read_text(encoding="utf-8")
    )
    block = ExabeamConfig.model_validate(document["configurations"]["exabeam"])
    again = ExabeamConfig.model_validate(block.model_dump(by_alias=True))
    assert again == block
    assert ExabeamConfig.model_validate(block.model_dump()) == block


def test_an_unknown_key_fails_load() -> None:
    with pytest.raises(ValidationError, match="tags"):
        ExabeamConfig.model_validate(_block(tags=["x"]))
    with pytest.raises(ValidationError, match="extra"):
        ExabeamConfig.model_validate(
            _block(
                sequences=[{"query": QUERY, "threshold": {**_threshold()[0]["threshold"], "x": 1}}]
            )
        )


def test_status_is_required() -> None:
    block = _block()
    del block["status"]
    with pytest.raises(ValidationError, match="status"):
        ExabeamConfig.model_validate(block)


@pytest.mark.parametrize(
    ("value", "units", "parsed"),
    [
        ("30m", "mhd", (30, "m")),
        ("4h", "mhd", (4, "h")),
        ("2w", "mhdw", (2, "w")),
        ("2w", "mhd", None),
        ("0m", "mhd", None),
        ("1h30m", "mhd", None),
        ("PT1H", "mhd", None),
        ("1 h", "mhd", None),
        (30, "mhd", None),
    ],
)
def test_duration(value: object, units: str, parsed: tuple[int, str] | None) -> None:
    assert duration(value, units) == parsed


@pytest.mark.parametrize(
    ("query", "found"),
    [
        ('user IN "Privileged Accounts"', True),
        ('src_ip in "Admin Users"."IP Address"', True),
        ("user IN 'Privileged Accounts'", True),
        ('activity_type:"app-login" AND NOT user IN "Service Accounts"', True),
        ('message:"log IN \\"x\\""', False),
        ('message:"sign IN" AND user:"x"', False),
        ('LOGIN:"x"', False),
        ('activity_type:"app-login"', False),
    ],
)
def test_uses_context_table(query: str, found: bool) -> None:
    assert uses_context_table(query) is found


# --- adversarial review of PR #983 ---------------------------------------------------------


@pytest.mark.parametrize("every", [["day"], {"day": 1}])
def test_a_list_or_map_under_every_is_exabeam_schedule(every: object) -> None:
    """An unhashable ``every`` is the constraint at its path, not a crash of the check."""
    block = _block(schedule=[{"every": every, "from": "08:00Z", "to": "17:00Z"}], severity="High")
    errors = _errors(block)
    assert ("exabeam_schedule", ("schedule", "0")) in errors
    assert ("exabeam_severity", ("severity",)) in errors


@pytest.mark.parametrize(
    "keys",
    [
        {"suppression": {"for_": "1h"}},
        {"schedule": [{"every": "day", "from_": "08:00Z", "to": "09:00Z"}]},
    ],
    ids=["for_", "from_"],
)
def test_the_python_names_of_keyword_keys_are_unknown_keys(keys: dict[str, Any]) -> None:
    """Only ``for`` and ``from`` are the YAML keys (exabeam-1.0: unknown keys fail)."""
    with pytest.raises(ValidationError):
        ExabeamConfig.model_validate(_block(**keys))


def test_a_null_attach_csv_or_correlation_group_by_is_the_key_left_out() -> None:
    """Both validate, as every other null does, and compile to their defaults."""
    from tests.test_platforms.test_exabeam_compile import _block_rule

    from opentide.models.deployment_enums import StatusStrategy
    from opentide.platforms.exabeam.compile import compile_body

    two = [{"query": QUERY}, {"query": QUERY}]
    block = ExabeamConfig.model_validate(
        _block(
            sequences=two,
            correlation={"within": "15m", "group_by": None},
            email={"recipients": ["soc@example.com"], "attach_csv": None},
        )
    )
    assert block.correlation is not None and not block.correlation.group_by
    assert block.email is not None and not block.email.attach_csv
    body = compile_body(
        _block_rule(
            _block(
                sequences=two,
                correlation={"within": "15m", "group_by": None},
                email={"recipients": ["soc@example.com"], "attach_csv": None},
            )
        ),
        StatusStrategy.RELEASE,
    )
    assert body["sequencesConfig"]["commonProperties"]["groupBy"] == []
    assert body["sequencesConfig"]["outcomes"]["email"]["attachCsv"] is False


def test_nested_unknown_keys_fail_as_unknown_keys_at_their_path() -> None:
    """exabeam-1.0: an unknown key is never a constraint code, at the block root or inside."""
    threshold = {"function": "count", "operator": "more_than", "value": 1, "within": "5m"}
    two = [{"query": QUERY}, {"query": QUERY}]
    cases = [
        ({"sequences": [{"query": QUERY, "extra": 1}]}, ("sequences", "0", "extra")),
        (
            {"sequences": [{"query": QUERY, "threshold": {**threshold, "extra": 1}}]},
            ("sequences", "0", "threshold", "extra"),
        ),
        ({"suppression": {"for": "1h", "unit": "h"}}, ("suppression", "unit")),
        (
            {"sequences": two, "correlation": {"within": "15m", "extra": 1}},
            ("correlation", "extra"),
        ),
        ({"email": {"recipients": ["a@b.co"], "cc": []}}, ("email", "cc")),
        (
            {"schedule": [{"every": "day", "from": "8:00Z", "to": "18:00Z", "tz": "UTC"}]},
            ("schedule", "0", "tz"),
        ),
    ]
    for keys, path in cases:
        assert _errors(_block(**keys)) == [("extra_forbidden", path)], keys
    # A day key the recurrence does not take is exabeam_schedule, not an unknown key.
    wrong_day_key = {"every": "day", "from": "8:00Z", "to": "18:00Z", "days": ["monday"]}
    assert _errors(_block(schedule=[wrong_day_key])) == [("exabeam_schedule", ("schedule", "0"))]


def test_a_suppression_that_is_not_a_table_is_reported_at_for() -> None:
    assert _errors(_block(suppression="1h")) == [("exabeam_duration", ("suppression", "for"))]
    assert _errors(_block(suppression={"group_by": ["user"]})) == [
        ("exabeam_duration", ("suppression", "for"))
    ]
