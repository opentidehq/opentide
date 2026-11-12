"""A Graylog block compiled to event-definition requests: the specification goldens and derivations.

The goldens under ``tests/fixtures/graylog/`` are the specification's
``fixtures/platforms/graylog/*.api.json``, sent to live Graylog 6.3.5 and 7.2.2
and accepted. Each is ``{method, path, body}``, built from a fixture rule and
the fixture tenant for one server version.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.rule import DetectionRule
from opentide.platforms.graylog.compile import (
    GraylogAliasError,
    attack_ids,
    compile_definition,
    create_request,
    derive_priority,
    is_vulnerable,
    normalise_tag,
    parse_version,
    update_request,
    validate_body,
)

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "graylog"
SAMPLE_ID = "65f1c0de2a3b4c5d6e7f8091"
AGGREGATION = "rule-graylog-aggregation-1.0.yaml"
FILTER = "rule-graylog-filter-1.1.yaml"

#: golden → (source rule, server version, operation), as the specification derives them.
GOLDENS = {
    "rule-graylog-aggregation-1.0.7.2.create.api.json": (AGGREGATION, "7.2.2", "create"),
    "rule-graylog-aggregation-1.0.7.2.update.api.json": (AGGREGATION, "7.2.2", "update"),
    "rule-graylog-aggregation-1.0.7.2.disable.api.json": (AGGREGATION, "7.2.2", "disable"),
    "rule-graylog-aggregation-1.0.7.0.create.api.json": (AGGREGATION, "7.0.16", "create"),
    "rule-graylog-aggregation-1.0.6.3.create.api.json": (AGGREGATION, "6.3.5", "create"),
    "rule-graylog-filter-1.1.7.1.create.api.json": (FILTER, "7.1.12", "create"),
    "rule-graylog-filter-1.1.6.3.create.api.json": (FILTER, "6.3.5", "create"),
}


def _setup(**overrides: Any) -> SimpleNamespace:
    document = tomllib.loads((FIXTURES / "tenant.toml").read_text(encoding="utf-8"))
    return SimpleNamespace(**{**document["tenants"][0]["setup"], **overrides})


def _rule(name: str) -> DetectionRule:
    return load_rule_from_dict(yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8")))


def _block_rule(block: dict[str, Any], **rule: Any) -> DetectionRule:
    document: dict[str, Any] = {
        "name": "Encoded PowerShell",
        "metadata": {
            "uuid": "11111111-2222-4333-8444-555555555555",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-11-10",
            "modified": "2026-11-10",
            "tlp": "clear",
        },
        "description": "PowerShell\n  started.",
        "configurations": {
            "graylog": {
                "status": "STAGING",
                "schema": "platform::graylog::1.0",
                "query": "EventID:1",
                **block,
            }
        },
        **rule,
    }
    return load_rule_from_dict(document)


def _version(text: str) -> tuple[int, int, int]:
    version = parse_version(text)
    assert version is not None
    return version


@pytest.mark.parametrize("golden", sorted(GOLDENS))
def test_requests_match_the_specification_goldens(golden: str) -> None:
    source, server, operation = GOLDENS[golden]
    compiled = compile_definition(_rule(source), _version(server), _setup())
    request = (
        create_request(compiled)
        if operation == "create"
        else update_request(compiled, SAMPLE_ID, enabled=operation != "disable")
    )
    assert request == json.loads((FIXTURES / golden).read_text(encoding="utf-8"))


def test_the_golden_set_is_complete() -> None:
    assert sorted(path.name for path in FIXTURES.glob("*.api.json")) == sorted(GOLDENS)


def test_version_differences() -> None:
    rule = _rule(AGGREGATION)
    v63 = create_request(compile_definition(rule, (6, 3, 5), _setup()))["body"]
    v72 = create_request(compile_definition(rule, (7, 2, 2), _setup()))["body"]["entity"]
    assert "entity" not in v63 and v63["share_request"] is None
    for key in ("tags", "tactics_techniques", "event_summary_template"):
        assert key not in v63
        assert key in v72
    assert "attack_techniques" in v63["field_spec"]
    assert "attack_techniques" not in v72["field_spec"]
    assert v72["tactics_techniques"] == ["T1059.001", "T1566.001", "TA0001", "TA0002"]
    assert v72["tags"][:2] == ["office", "initial-access"]
    filter_rule = _rule(FILTER)
    assert (
        create_request(compile_definition(filter_rule, (6, 3, 5), _setup()))["body"]["priority"]
        == 1
    )
    assert (
        create_request(compile_definition(filter_rule, (7, 1, 12), _setup()))["body"]["entity"][
            "priority"
        ]
        == 0
    )


def test_no_body_carries_a_server_owned_property_or_a_create_id() -> None:
    for version in ((6, 3, 5), (7, 0, 16), (7, 1, 12), (7, 2, 2)):
        compiled = compile_definition(_rule(AGGREGATION), version, _setup())
        body = create_request(compiled)["body"]
        definition = body.get("entity", body)
        assert definition["_scope"] == "DEFAULT"
        assert "id" not in definition
        forbidden = {"state", "storage", "scheduler", "updated_at", "matched_at", "_entity_source"}
        assert not forbidden & set(definition)
        assert not any(
            "exclude_empty_fields" in provider
            for spec in definition["field_spec"].values()
            for provider in spec["providers"]
        )


def test_version_warnings() -> None:
    compiled = compile_definition(_rule(AGGREGATION), (6, 3, 5), _setup())
    assert [code for code, _ in compiled.warnings] == [
        "graylog_field_unsupported_version",
        "graylog_field_unsupported_version",
    ]
    assert compile_definition(_rule(AGGREGATION), (7, 2, 2), _setup()).warnings == ()
    collapsed = compile_definition(_rule(FILTER), (7, 0, 16), _setup())
    assert [code for code, _ in collapsed.warnings] == ["graylog_priority_collapsed"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("6.3.5+eaa4b5d", (6, 3, 5)),
        ("7.2.2+94adc86", (7, 2, 2)),
        ("7.1", (7, 1, 0)),
        ("7.0.16-SNAPSHOT", (7, 0, 16)),
        ("", None),
        (None, None),
        ("seven", None),
    ],
)
def test_parse_version(text: object, expected: tuple[int, int, int] | None) -> None:
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    ("version", "vulnerable"),
    [
        ((6, 3, 5), True),
        ((6, 3, 12), False),
        ((7, 0, 15), True),
        ((7, 0, 16), False),
        ((7, 1, 11), True),
        ((7, 1, 12), False),
        ((7, 2, 0), False),
    ],
)
def test_vulnerable_versions(version: tuple[int, int, int], vulnerable: bool) -> None:
    assert is_vulnerable(version) is vulnerable


@pytest.mark.parametrize(
    ("label", "version", "priority"),
    [
        ("Critical", (7, 2, 0), 4),
        ("High", (6, 3, 0), 3),
        ("Medium", (7, 0, 0), 2),
        ("Low", (7, 1, 0), 1),
        ("Informational", (7, 1, 0), 0),
        ("Informational", (7, 0, 16), 1),
        (None, (7, 2, 0), 2),
        ("high", (7, 2, 0), 3),
    ],
)
def test_priority(label: str | None, version: tuple[int, int, int], priority: int) -> None:
    assert derive_priority(label, version) == priority


def test_the_block_priority_wins_over_the_severity() -> None:
    rule = _block_rule({"priority": "Low"}, response={"alert_severity": "Critical"})
    assert compile_definition(rule, (7, 2, 0)).definition["priority"] == 1


def test_a_rule_without_a_severity_is_medium() -> None:
    assert compile_definition(_block_rule({}), (7, 2, 0)).definition["priority"] == 2


def test_tags_are_normalised_unique_and_capped() -> None:
    assert normalise_tag("Initial Access!") == "initial-access-"
    assert len(normalise_tag("x" * 300)) == 128
    rule = _block_rule({"tags": ["Office", "office", *[f"t{n}" for n in range(80)]]})
    tags = compile_definition(rule, (7, 2, 0), _setup(tags="extra")).definition["tags"]
    assert tags[0] == "office"
    assert len(tags) == 64
    assert tags.count("office") == 1
    # The cap keeps the first 64 in the spec's order: the block's own tags come first.
    assert "opentide" not in tags
    few = compile_definition(_block_rule({"tags": "Office"}), (7, 2, 0), _setup(tags="extra"))
    assert few.definition["tags"] == [
        "office",
        "opentide",
        "opentide.11111111-2222-4333-8444-555555555555",
        "extra",
    ]


def test_a_string_tenant_tag_is_one_tag() -> None:
    tags = compile_definition(_block_rule({}), (7, 2, 0), _setup(tags="soc")).definition["tags"]
    assert tags[-1] == "soc"


def test_a_block_attack_techniques_field_is_kept() -> None:
    rule = _block_rule(
        {"event_fields": {"attack_techniques": {"template": "custom"}}},
        techniques=["T1059.001"],
    )
    spec = compile_definition(rule, (6, 3, 5), _setup()).definition["field_spec"]
    assert spec["attack_techniques"]["providers"][0]["template"] == "custom"


def test_attack_ids_are_enterprise_techniques_then_their_tactics() -> None:
    assert attack_ids(_rule(AGGREGATION)) == ["T1059.001", "T1566.001", "TA0001", "TA0002"]
    assert attack_ids(_block_rule({})) == []


def test_without_attack_ids_the_description_has_no_attack_line() -> None:
    compiled = compile_definition(_block_rule({}), (6, 3, 5), _setup())
    assert compiled.definition["description"] == "PowerShell started."
    assert "attack_techniques" not in compiled.definition["field_spec"]


def test_schedule_defaults_and_cron() -> None:
    config = compile_definition(_block_rule({}), (7, 2, 0), _setup()).config
    assert (config["search_within_ms"], config["execute_every_ms"]) == (300000, 300000)
    assert config["use_cron_scheduling"] is False
    assert config["event_limit"] == 100
    assert "cron_expression" not in config
    cron = _block_rule({"schedule": {"cron": "0 0 * * * ?", "window": "1h"}})
    config = compile_definition(cron, (7, 2, 0), _setup()).config
    assert config["cron_expression"] == "0 0 * * * ?"
    assert config["cron_timezone"] == "UTC"
    assert config["execute_every_ms"] == config["search_within_ms"] == 3600000


def test_the_block_streams_win_over_the_tenant_streams() -> None:
    rule = _block_rule({"streams": "windows-security", "stream_categories": "edr"})
    config = compile_definition(rule, (7, 2, 0), _setup()).config
    assert config["streams"] == ["65f0c0ffee0123456789abce"]
    assert config["stream_categories"] == ["edr"]


@pytest.mark.parametrize(
    ("block", "alias"),
    [({"streams": "nowhere"}, "nowhere"), ({"notifications": ["soc-teams"]}, "soc-teams")],
)
def test_an_unknown_alias_is_graylog_alias_unknown(block: dict[str, Any], alias: str) -> None:
    with pytest.raises(GraylogAliasError) as caught:
        compile_definition(_block_rule(block), (7, 2, 0), _setup(), tenant="graylog-prod")
    assert caught.value.code == "graylog_alias_unknown"
    assert alias in caught.value.reason and "'graylog-prod'" in caught.value.reason


def test_without_a_tenant_the_aliases_are_unresolved_never_sent() -> None:
    compiled = compile_definition(_rule(AGGREGATION), (7, 2, 0))
    assert compiled.config["streams"] == []
    assert compiled.definition["notifications"] == []
    assert compiled.unresolved == {"streams": ["sysmon"], "notifications": ["soc-slack"]}
    assert "managed-by-opentide" not in compiled.definition["tags"]


def test_the_pre_save_check_names_streams_categories_and_the_window() -> None:
    compiled = compile_definition(_rule(AGGREGATION), (7, 2, 0), _setup())
    assert validate_body(compiled) == {
        "query": compiled.config["query"],
        "streams": ["65f0c0ffee0123456789abcd"],
        "stream_categories": [],
        "timerange": {"type": "relative", "range": 900},
    }


def test_the_uuid_tag_is_named_on_7_2_only() -> None:
    uuid_tag = "opentide.00000000-0000-4000-8003-000000000060"
    assert compile_definition(_rule(AGGREGATION), (7, 2, 0), _setup()).uuid_tag == uuid_tag
    assert compile_definition(_rule(AGGREGATION), (7, 1, 0), _setup()).uuid_tag is None
