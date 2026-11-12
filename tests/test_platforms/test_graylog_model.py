"""The Graylog block model: constraint codes at their spec paths, and the condition grammar.

Every code is reported at the ``field_path`` graylog-1.0 fixes for it, so
``opentide validate`` and the editor name the same finding.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from opentide.loading.platform_loader import load_platform_config
from opentide.models.platform import GraylogConfig
from opentide.platforms.graylog.constraints import (
    CONSTRAINT_CODES,
    ConditionError,
    as_list,
    block_findings,
    cron_ok,
    duration_ms,
    event_field_kind,
    list_ok,
    parse_condition,
    timezone_ok,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "graylog"


def _block(**keys: Any) -> dict[str, Any]:
    return {
        "enabled": True,
        "schema": "platform::graylog::1.0",
        "status": "STAGING",
        "query": "EventID:1",
        **keys,
    }


def _codes(**keys: Any) -> set[str]:
    return {finding.code for finding in block_findings(_block(**keys))}


def _errors(block: dict[str, Any]) -> list[tuple[str, tuple[Any, ...]]]:
    with pytest.raises(ValidationError) as caught:
        GraylogConfig.model_validate(block)
    return [(error["type"], error["loc"]) for error in caught.value.errors()]


# --- the reference cases (specifications scripts/test_platform_graylog.py) -----------------


@pytest.mark.parametrize(
    ("keys", "expected"),
    [
        ({}, set()),
        ({"query": "  "}, {"graylog_query_blank"}),
        ({"streams": "sysmon"}, set()),
        ({"streams": ["a", "a"]}, {"graylog_list_shape"}),
        ({"notifications": [""]}, {"graylog_list_shape"}),
        ({"priority": "Urgent"}, {"graylog_priority"}),
        ({"event_limit": 0}, {"graylog_event_limit"}),
        ({"event_limit": 10, "aggregation": {"condition": "count() > 1"}}, {"graylog_event_limit"}),
        ({"schedule": {"every": "0m"}}, {"graylog_schedule"}),
        ({"schedule": {"cron": "0 */5 * * * ?"}}, {"graylog_schedule"}),
        (
            {"schedule": {"cron": "0 */5 * * * ?", "window": "5m", "timezone": "Mars/Base"}},
            {"graylog_schedule"},
        ),
        ({"schedule": {"every": "PT5M", "window": "1h10m"}}, set()),
        ({"aggregation": {"group_by": "source"}}, {"graylog_aggregation"}),
        (
            {"aggregation": {"group_by": ["src ip"], "condition": "count() > 1"}},
            {"graylog_field_name"},
        ),
        (
            {
                "event_fields": {
                    "host": "source",
                    "x": "${source.a}-${source.b}",
                    "y": {"template": "LOLBin"},
                }
            },
            set(),
        ),
        ({"event_fields": {"owner": {"lookup": {"table": "t", "key_field": "source"}}}}, set()),
        ({"event_fields": {"x": "two words"}}, {"graylog_event_field"}),
        ({"event_fields": {"x": {"lookup": {"table": "t"}}}}, {"graylog_event_field"}),
        ({"event_fields": {"host": "source"}, "event_key": "host"}, set()),
        ({"event_fields": {"host": "source"}, "event_key": ["user"]}, {"graylog_event_key"}),
    ],
)
def test_block_codes(keys: dict[str, Any], expected: set[str]) -> None:
    assert _codes(**keys) == expected


@pytest.mark.parametrize(
    ("keys", "code", "path"),
    [
        ({"query": ""}, "graylog_query_blank", ("query",)),
        ({"tags": ["x", "x"]}, "graylog_list_shape", ("tags",)),
        ({"stream_categories": [1]}, "graylog_list_shape", ("stream_categories",)),
        (
            {"aggregation": {"group_by": ["a", "a"], "condition": "count() > 1"}},
            "graylog_list_shape",
            ("aggregation", "group_by"),
        ),
        ({"schedule": {"every": "5m", "cron": "0 0 * * * ?"}}, "graylog_schedule", ("schedule",)),
        ({"schedule": "5m"}, "graylog_schedule", ("schedule",)),
        ({"schedule": {"every": "1w"}}, "graylog_schedule", ("schedule", "every")),
        ({"schedule": {"window": "0s"}}, "graylog_schedule", ("schedule", "window")),
        (
            {"schedule": {"cron": "*/5 * * * *", "window": "5m"}},
            "graylog_schedule",
            ("schedule", "cron"),
        ),
        ({"schedule": {"cron": "0 0 * * * ?"}}, "graylog_schedule", ("schedule", "window")),
        (
            {"schedule": {"every": "5m", "timezone": "Nowhere/City"}},
            "graylog_schedule",
            ("schedule", "timezone"),
        ),
        ({"event_limit": 1001}, "graylog_event_limit", ("event_limit",)),
        ({"event_limit": True}, "graylog_event_limit", ("event_limit",)),
        ({"aggregation": {}}, "graylog_aggregation", ("aggregation",)),
        (
            {"aggregation": {"condition": "count() >= 3 or count() < 9"}},
            "graylog_aggregation",
            ("aggregation", "condition"),
        ),
        (
            {"event_fields": {"bad name": "source"}},
            "graylog_event_field",
            ("event_fields", "bad name"),
        ),
        ({"event_fields": ["source"]}, "graylog_event_field", ("event_fields",)),
        ({"event_fields": {"x": {"template": " "}}}, "graylog_event_field", ("event_fields", "x")),
        ({"event_key": "host"}, "graylog_event_key", ("event_key",)),
        ({"priority": "high"}, "graylog_priority", ("priority",)),
        (
            {"aggregation": {"group_by": "src ip", "condition": "count() > 1"}},
            "graylog_field_name",
            ("aggregation", "group_by"),
        ),
    ],
)
def test_each_code_is_reported_at_its_spec_path(
    keys: dict[str, Any], code: str, path: tuple[str, ...]
) -> None:
    assert (code, path) in _errors(_block(**keys))


def test_every_constraint_code_has_a_case() -> None:
    assert {
        "graylog_query_blank",
        "graylog_list_shape",
        "graylog_schedule",
        "graylog_event_limit",
        "graylog_aggregation",
        "graylog_event_field",
        "graylog_event_key",
        "graylog_priority",
        "graylog_field_name",
    } == CONSTRAINT_CODES


def test_a_missing_query_is_graylog_query_blank() -> None:
    block = _block()
    del block["query"]
    assert ("graylog_query_blank", ("query",)) in _errors(block)


def test_status_is_required() -> None:
    block = _block()
    del block["status"]
    assert ("missing", ("status",)) in _errors(block)


# --- unknown keys --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "keys",
    [
        {"rule_type": "filter"},
        {"schedule": {"every": "5m", "interval": "5m"}},
        {"aggregation": {"condition": "count() > 1", "series": []}},
    ],
)
def test_unknown_keys_fail(keys: dict[str, Any]) -> None:
    assert any(kind == "extra_forbidden" for kind, _ in _errors(_block(**keys)))


def test_an_unknown_key_in_an_event_field_map_fails() -> None:
    errors = _errors(_block(event_fields={"x": {"template": "a", "require_values": True}}))
    assert ("graylog_event_field", ("event_fields", "x")) in errors


def test_legacy_external_id_keys_are_dropped_by_the_loader_for_validate_to_report() -> None:
    """``rule_id::<tenant>`` is ``external_id_in_rule`` (validate), never a block field."""
    block = _block(**{"rule_id::graylog-prod": "65f1c0de2a3b4c5d6e7f8091"})
    loaded = load_platform_config("graylog", block)
    assert isinstance(loaded, GraylogConfig)
    assert "rule_id::graylog-prod" not in loaded.model_dump(by_alias=True)


def test_a_dump_validates_again() -> None:
    """Deploy planning dumps a rule to apply modifiers: nulls the author never wrote pass."""
    block = yaml.safe_load((FIXTURES / "rule-graylog-aggregation-1.0.yaml").read_text())
    loaded = GraylogConfig.model_validate(block["configurations"]["graylog"])
    again = GraylogConfig.model_validate(loaded.model_dump(mode="json", by_alias=True))
    assert again == loaded


def test_a_bad_grace_period_fails() -> None:
    with pytest.raises(ValidationError):
        GraylogConfig.model_validate(_block(grace_period="soon"))
    assert GraylogConfig.model_validate(_block(grace_period="0s")).grace_period == "0s"


def test_backlog_is_zero_or_more() -> None:
    with pytest.raises(ValidationError):
        GraylogConfig.model_validate(_block(backlog=-1))


# --- the specification fixtures ------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["block-graylog.yaml", "rule-graylog-aggregation-1.0.yaml", "rule-graylog-filter-1.1.yaml"],
)
def test_valid_fixtures_load(name: str) -> None:
    document = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    assert block_findings(document["configurations"]["graylog"]) == []
    GraylogConfig.model_validate(document["configurations"]["graylog"])


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("rule-graylog-condition.yaml", "graylog_aggregation"),
        ("rule-graylog-event-field.yaml", "graylog_event_field"),
        ("rule-graylog-event-key.yaml", "graylog_event_key"),
        ("rule-graylog-schedule.yaml", "graylog_schedule"),
    ],
)
def test_invalid_fixtures_report_their_code(name: str, code: str) -> None:
    document = yaml.safe_load((FIXTURES / "invalid" / name).read_text(encoding="utf-8"))
    assert code in {
        finding.code for finding in block_findings(document["configurations"]["graylog"])
    }


# --- list fields, durations, cron, time zones ----------------------------------------------


def test_a_string_is_a_one_item_list() -> None:
    assert as_list("sysmon") == ["sysmon"]
    assert as_list(["a", "b"]) == ["a", "b"]
    assert as_list(None) == []
    assert list_ok([]) and list_ok("x") and not list_ok({"a": 1}) and not list_ok(["a", 1])


@pytest.mark.parametrize(
    ("text", "seconds"), [("1h10m", 4200), ("PT1H10M", 4200), ("P1DT2H", 93600), ("5m", 300)]
)
def test_duration_grammar(text: str, seconds: int) -> None:
    assert duration_ms(text) == seconds * 1000


@pytest.mark.parametrize("bad", ["", "5", "1w", "m5", "PT", "P", "1.5h", "-5m", "5 m"])
def test_duration_grammar_refusals(bad: str) -> None:
    with pytest.raises(ValueError):
        duration_ms(bad)


@pytest.mark.parametrize(
    "cron",
    [
        "0 */5 * * * ?",
        "0 */10 * * * ?",
        "0 0 12 ? * MON-FRI",
        "0 15 10 ? * 6L 2026",
        "0 0 8 L * ?",
        "0 0 8 15W * ?",
        "0 0 8 ? * 2#1",
        "0 0,30 8-17 ? JAN-MAR *",
        "0 0 0 1 1/3 ? *",
    ],
)
def test_quartz_expressions(cron: str) -> None:
    assert cron_ok(cron)


@pytest.mark.parametrize(
    "cron",
    [
        "*/5 * * * *",
        "0 0 * * * *",
        "0 0 * ? * ?",
        "60 0 * * * ?",
        "0 0 24 * * ?",
        "0 0 0 32 * ?",
        "0 0 0 ? 13 *",
        "0 0 0 ? * 8",
        "0 0 0 ? * MON#6",
        "0 0 0 * * ? 1969",
        "0 0/0 * * * ?",
        "0 0 0 * * ? * *",
        7,
    ],
)
def test_quartz_refusals(cron: object) -> None:
    assert not cron_ok(cron)


def test_time_zones() -> None:
    assert timezone_ok("UTC") and timezone_ok("Europe/Paris")
    assert not timezone_ok("Mars/Base") and not timezone_ok("") and not timezone_ok(3)


def test_without_a_zone_database_a_zone_shaped_name_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zoneinfo

    def missing(name: str) -> object:
        raise zoneinfo.ZoneInfoNotFoundError(name)

    monkeypatch.setattr(zoneinfo, "ZoneInfo", missing)
    monkeypatch.setattr(zoneinfo, "available_timezones", lambda: set())
    assert timezone_ok("Europe/Paris")
    assert not timezone_ok("not a zone")


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("source", "field"),
        ("winlog.event_data.User", "field"),
        ("${source.User}@${source.Domain}", "template"),
        ({"template": "LOLBin"}, "template"),
        ({"lookup": {"table": "owners", "key_field": "source"}}, "lookup"),
        ("two words", None),
        ({"template": ""}, None),
        ({"lookup": {"table": "owners", "key_field": ""}}, None),
        ({"template": "a", "lookup": {}}, None),
        (3, None),
    ],
)
def test_event_field_value_forms(value: object, kind: str | None) -> None:
    assert event_field_kind(value) == kind


# --- the condition grammar -----------------------------------------------------------------


def test_the_condition_compiles_to_graylog_tree() -> None:
    tree, series = parse_condition("count() >= 3 OR card(parent_image_lc) >= 2")
    assert series == [
        {"id": "count-", "type": "count"},
        {"id": "card-parent_image_lc", "type": "card", "field": "parent_image_lc"},
    ]
    assert tree["expr"] == "||"
    assert tree["left"] == {
        "expr": ">=",
        "left": {"expr": "number-ref", "ref": "count-"},
        "right": {"expr": "number", "value": 3},
    }


def test_precedence_and_reuse() -> None:
    tree, series = parse_condition(
        "NOT count() > 1 AND count() < 10 OR percentile(bytes, 95) > 2.5"
    )
    assert [entry["id"] for entry in series] == ["count-", "percentile-bytes-95"]
    assert series[1]["percentile"] == 95.0
    assert tree["expr"] == "||"
    assert tree["left"]["expr"] == "&&"
    assert tree["left"]["left"]["expr"] == "!"
    assert tree["right"]["right"] == {"expr": "number", "value": 2.5}


def test_parentheses_only_group_and_and_is_left_associative() -> None:
    tree, series = parse_condition("(count(a) > 1 AND sum(b) > 2) AND max(c) == -1")
    assert tree["expr"] == "&&"
    assert tree["left"]["expr"] == "&&"
    assert tree["right"]["right"] == {"expr": "number", "value": -1}
    assert [entry["type"] for entry in series] == ["count", "sum", "max"]
    assert series[0] == {"id": "count-a", "type": "count", "field": "a"}


@pytest.mark.parametrize(
    "function", ["avg", "latest", "min", "percentage", "stddev", "sumofsquares", "variance"]
)
def test_every_one_field_function(function: str) -> None:
    _, series = parse_condition(f"{function}(bytes) > 1")
    assert series == [{"id": f"{function}-bytes", "type": function, "field": "bytes"}]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "count() >= 3 or count() < 9",
        "total(bytes) > 1",
        "avg() > 1",
        "count(a, b) > 1",
        "percentile(bytes) > 1",
        "percentile(bytes, 101) > 1",
        "percentile(bytes, 0) > 1",
        "count() >= ",
        "(count() > 1",
        "count() = 1",
        "count() > 1 count() > 2",
        "count(src ip) > 1",
        "count() > 1.",
        "count() > x",
        "count() > 1 $",
        # Arguments are comma separated (graylog-1.1): no missing or trailing comma.
        "percentile(bytes 95) > 1",
        "count(x,) > 1",
        "percentile(bytes, 95,) > 1",
        "max(,a) > 1",
        # Parentheses and NOT nest at most 32 deep.
        "(" * 33 + "count() > 1" + ")" * 33,
        "NOT " * 33 + "count() > 1",
    ],
)
def test_condition_refusals(text: str) -> None:
    with pytest.raises(ConditionError):
        parse_condition(text)


@pytest.mark.parametrize(
    "text",
    [
        "(" * 5000 + "count() > 1" + ")" * 5000,
        "NOT " * 50_000 + "count() > 1",
    ],
)
def test_a_deeply_nested_condition_is_refused_not_a_recursion_error(text: str) -> None:
    with pytest.raises(ConditionError, match="nests deeper than 32"):
        parse_condition(text)


def test_nesting_up_to_the_limit_parses() -> None:
    tree, _ = parse_condition("(" * 32 + "count() > 1" + ")" * 32)
    assert tree["expr"] == ">"
    tree, _ = parse_condition("NOT " * 32 + "count() > 1")
    assert tree["expr"] == "!"
