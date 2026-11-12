"""GoogleSecopsConfig, its constraint codes and the YARA-L section checks.

google-secops-1.0 (Constraints, Advisories) and yara-l-1.0 (YaraLSections,
YaraLMatch, YaraLOptions): each code is reported at the field path the spec
fixes for it, relative to ``configurations.google_secops``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from opentide.loading.platform_loader import load_platform_config
from opentide.models.platform import (
    PLATFORM_CONFIG_MODELS,
    GoogleSecopsConfig,
    RuleConfigurations,
)
from opentide.platforms.google_secops.advisories import google_secops_advisories
from opentide.platforms.google_secops.yaral import (
    code_lines,
    event_variables,
    render_match,
    section_header_line,
)
from opentide.validation.google_secops import (
    aliased_sections,
    google_secops_name_issues,
    section_alias_issues,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "google_secops"
EVENTS = '$e.metadata.event_type = "USER_LOGIN"\n'

#: The code each specification invalid fixture names in its header.
INVALID = {
    "rule-google-secops-section-header.yaml": "yaral_section_header",
    "rule-google-secops-condition-comment.yaml": "yaral_section_empty",
    "rule-google-secops-sliding-no-pivot.yaml": "yaral_match_shape",
    "rule-google-secops-missing-condition.yaml": "yaral_section_missing",
    "rule-google-secops-hourly.yaml": "google_secops_run_frequency",
    "rule-google-secops-meta-reserved.yaml": "google_secops_meta_key",
}


def _block(**keys: Any) -> dict[str, Any]:
    block = {
        "enabled": True,
        "schema": "platform::google_secops::1.0",
        "status": "STAGING",
        "events": EVENTS,
        "condition": "$e\n",
    }
    block.update(keys)
    return {key: value for key, value in block.items() if value is not ...}


def _errors(block: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    """``(code, field_path)`` for each finding, as validate reports them."""
    with pytest.raises(ValidationError) as caught:
        GoogleSecopsConfig.model_validate(block)
    return [(error["type"], tuple(map(str, error["loc"]))) for error in caught.value.errors()]


def _codes(block: dict[str, Any]) -> set[str]:
    return {code for code, _ in _errors(block)}


def test_google_secops_is_a_registered_platform() -> None:
    assert PLATFORM_CONFIG_MODELS["google_secops"] is GoogleSecopsConfig
    assert GoogleSecopsConfig.schema_identifier() == "platform::google_secops::1.0"
    assert "google_secops" in RuleConfigurations.model_fields


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.yaml")))
def test_the_specification_fixtures_validate(name: str) -> None:
    document = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    block = load_platform_config("google_secops", document["configurations"]["google_secops"])
    assert isinstance(block, GoogleSecopsConfig)


@pytest.mark.parametrize(("name", "code"), sorted(INVALID.items()))
def test_the_specification_invalid_fixtures_report_their_code(name: str, code: str) -> None:
    document = yaml.safe_load((FIXTURES / "invalid" / name).read_text(encoding="utf-8"))
    assert code in _codes(document["configurations"]["google_secops"])


def test_the_hourly_fixture_also_reports_its_schedule() -> None:
    document = yaml.safe_load(
        (FIXTURES / "invalid" / "rule-google-secops-hourly.yaml").read_text(encoding="utf-8")
    )
    assert _errors(document["configurations"]["google_secops"]) == [
        ("google_secops_run_frequency", ("run_frequency",)),
        ("google_secops_schedule", ("schedule",)),
    ]


def test_a_minimal_block_validates() -> None:
    block = GoogleSecopsConfig.model_validate(_block())
    assert block.events == EVENTS
    assert block.match is None


def test_omitted_status_is_the_missing_field_not_a_code() -> None:
    with pytest.raises(ValidationError) as caught:
        GoogleSecopsConfig.model_validate({"events": EVENTS, "condition": "$e"})
    assert [e["loc"] for e in caught.value.errors()] == [("status",)]
    with pytest.raises(ValidationError) as caught:
        GoogleSecopsConfig.model_validate({"events": EVENTS})
    assert [e["loc"] for e in caught.value.errors()] == [("status",), ("condition",)]


@pytest.mark.parametrize(
    ("keys", "expected"),
    [
        ({"name": "bad-name"}, [("google_secops_rule_name", ("name",))]),
        ({"name": "Match"}, [("google_secops_rule_name", ("name",))]),
        ({"severity": "Informational"}, [("google_secops_severity", ("severity",))]),
        ({"priority": "urgent"}, [("google_secops_severity", ("priority",))]),
        ({"run_frequency": "HOURLY"}, [("google_secops_run_frequency", ("run_frequency",))]),
        (
            {"run_frequency": "LIVE", "schedule": {"ensure_enrichment_completeness": True}},
            [("google_secops_schedule", ("schedule",))],
        ),
        (
            {
                "run_frequency": "HOURLY_CUSTOMIZABLE",
                "schedule": {"late_arriving_data_adjustment": "soon"},
            },
            [("google_secops_schedule", ("schedule", "late_arriving_data_adjustment"))],
        ),
        ({"meta": {"technique": "x"}}, [("google_secops_meta_key", ("meta", "technique"))]),
        ({"meta": {"opentide_uuid": "x"}}, [("google_secops_meta_key", ("meta", "opentide_uuid"))]),
        ({"meta": {"not-an-id": "x"}}, [("google_secops_meta_key", ("meta", "not-an-id"))]),
        ({"meta": {"or": "x"}}, [("google_secops_meta_key", ("meta", "or"))]),
        ({"meta": {"count": 3}}, [("google_secops_meta_key", ("meta", "count"))]),
        ({"condition": ...}, [("yaral_section_missing", ("condition",))]),
        ({"events": ...}, [("yaral_section_missing", ("events",))]),
        ({"condition": None}, [("yaral_section_empty", ("condition",))]),
        ({"outcome": "  \n"}, [("yaral_section_empty", ("outcome",))]),
        ({"outcome": ["$x = 1"]}, [("yaral_section_empty", ("outcome",))]),
        (
            {"events": 'events:\n  $e.metadata.event_type = "X"\n'},
            [("yaral_section_header", ("events",))],
        ),
        (
            {"condition": "$e\noptions:\n  allow_zero_values = true\n"},
            [("yaral_section_header", ("condition",))],
        ),
        ({"condition": "{\n$e\n}\n"}, [("yaral_section_header", ("condition",))]),
        (
            {"match": {"group_by": ["$u"], "window": "15d"}},
            [("yaral_match_window", ("match", "window"))],
        ),
        (
            {"match": {"group_by": ["$u"], "window": "4d", "type": "tumbling"}},
            [("yaral_match_window", ("match", "window"))],
        ),
        (
            {"match": {"group_by": ["$u"], "window": "10s"}},
            [("yaral_match_window", ("match", "window"))],
        ),
        (
            {"match": {"group_by": [], "window": "10m"}},
            [("yaral_match_shape", ("match", "group_by"))],
        ),
        (
            {"match": {"group_by": ["u"], "window": "10m"}},
            [("yaral_match_shape", ("match", "group_by"))],
        ),
        (
            {"match": {"group_by": ["$u", "$u"], "window": "10m"}},
            [("yaral_match_shape", ("match", "group_by"))],
        ),
        (
            {"match": {"group_by": ["$u"], "window": "10m", "type": "sliding"}},
            [("yaral_match_shape", ("match",))],
        ),
        (
            {"match": {"group_by": ["$u"], "window": "10m", "pivot": "$e"}},
            [("yaral_match_shape", ("match", "pivot"))],
        ),
        (
            {"match": {"group_by": ["$u"], "window": "10m", "type": "rolling"}},
            [("yaral_match_shape", ("match", "type"))],
        ),
        (
            {"match": {"group_by": ["$u"], "window": "10m", "by": "x"}},
            [("yaral_match_shape", ("match", "by"))],
        ),
        ({"match": "$u over 10m"}, [("yaral_match_shape", ("match",))]),
        (
            {"options": {"allow_zero_values": "yes"}},
            [("yaral_option", ("options", "allow_zero_values"))],
        ),
        ({"options": {"allow_nulls": True}}, [("yaral_option", ("options", "allow_nulls"))]),
        (
            {"options": {"suppression_window": "1 hour"}},
            [("yaral_option", ("options", "suppression_window"))],
        ),
        ({"options": "allow_zero_values = true"}, [("yaral_option", ("options",))]),
        ({"query": "events:\n  $e\n"}, [("extra_forbidden", ("query",))]),
    ],
)
def test_each_code_at_its_field_path(
    keys: dict[str, Any], expected: list[tuple[str, tuple[str, ...]]]
) -> None:
    assert _errors(_block(**keys)) == expected


@pytest.mark.parametrize(
    "keys",
    [
        {"match": {"group_by": ["$u"], "window": "3d"}},
        {"match": {"group_by": ["$u"], "window": "14d"}},
        {"match": {"group_by": ["$u"], "window": "72h", "type": "tumbling"}},
        {
            "match": {"group_by": ["$u"], "window": "10m", "type": "sliding", "pivot": "$e"}
            | {"direction": "after"}
        },
        {
            "run_frequency": "HOURLY_CUSTOMIZABLE",
            "schedule": {"late_arriving_data_adjustment": "2h"},
        },
        {"options": {"allow_zero_values": False, "suppression_window": "1d"}},
        {"events": '$e.metadata.description = "condition: none" // match: in a comment\n'},
        {"events": "$e.metadata.description = /rule x \\{/\n"},
        {"name": "my_rule", "meta": {"data_source": "Okta"}},
        # tactic is not derived (google-secops-1.1): a block may set its own.
        {"meta": {"tactic": "TA0006"}},
        {"severity": "Info", "priority": "Critical", "alerting": True},
    ],
)
def test_valid_blocks(keys: dict[str, Any]) -> None:
    GoogleSecopsConfig.model_validate(_block(**keys))


def test_the_empty_message_explains_the_yaml_comment() -> None:
    with pytest.raises(ValidationError) as caught:
        GoogleSecopsConfig.model_validate(_block(condition=None))
    assert "a plain YAML scalar that starts with # is a YAML comment" in str(caught.value)


def test_every_finding_is_reported_at_once() -> None:
    codes = _codes(_block(name="9x", severity="x", condition=..., options={"x": 1}))
    assert codes == {
        "google_secops_rule_name",
        "google_secops_severity",
        "yaral_section_missing",
        "yaral_option",
    }


def test_the_scanner_keeps_columns_and_ignores_literals() -> None:
    text = '$e.x = "a // b" // c\n$e.y = /x\\/y/ nocase /* d\nstill */ and $n / 2\n'
    lines = code_lines(text)
    assert [len(line) for line in lines] == [len(line) for line in text.split("\n")]
    assert "//" not in lines[0].replace('"', "")
    assert "x" not in lines[1].split("=", 1)[1].replace("nocase", "")
    assert lines[2].strip().endswith("and $n / 2")
    assert section_header_line("$e\n  // events: commented\n") is None
    assert section_header_line("$e\nRULE x {\n") == 2
    assert render_match({"group_by": ["$user", "$ip"], "window": "30m"}) == "$user, $ip over 30m"


def test_event_variables() -> None:
    events = '$a.metadata.x = "$z.q"\n$p = $b.principal.ip\n// $c.ignored\n'
    assert event_variables(events) == ["a", "b"]
    assert event_variables(None) == []


# --- advisories --------------------------------------------------------------------


def _rule(**block: Any) -> dict[str, Any]:
    return {"configurations": {"google_secops": _block(**block)}}


def test_the_risk_score_advisory() -> None:
    assert [a.code for a in google_secops_advisories(_rule())] == [
        "google_secops_risk_score_missing"
    ]
    found = google_secops_advisories(_rule(outcome="$host = $e.principal.hostname\n"))
    assert [(a.code, a.field_path[-1]) for a in found] == [
        ("google_secops_risk_score_missing", "outcome")
    ]
    assert google_secops_advisories(_rule(outcome="$risk_score = 40\n")) == []
    commented = "// $risk_score = 40\n$x = 1\n"
    assert len(google_secops_advisories(_rule(outcome=commented))) == 1


def test_the_rule_id_literal_advisory() -> None:
    literal = '$d.detection.detection.rule_id = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1"\n'
    found = google_secops_advisories(_rule(events=literal, outcome="$risk_score = 1\n"))
    assert [(a.code, a.field_path[-1]) for a in found] == [
        ("google_secops_rule_id_literal", "events")
    ]
    by_name = '$d.detection.detection.rule_name = "password_spray"\n'
    assert google_secops_advisories(_rule(events=by_name, outcome="$risk_score = 1\n")) == []
    commented = (
        '$e.x = "y" // detection.detection.rule_id = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1"\n'
    )
    assert google_secops_advisories(_rule(events=commented, outcome="$risk_score = 1\n")) == []


def test_the_live_frequency_advisory() -> None:
    two = '$a.metadata.event_type = "X"\n$b.metadata.event_type = "Y"\n'
    found = google_secops_advisories(
        _rule(events=two, run_frequency="LIVE", outcome="$risk_score = 1\n")
    )
    assert [a.code for a in found] == ["google_secops_live_frequency_unavailable"]
    one = google_secops_advisories(_rule(run_frequency="LIVE", outcome="$risk_score = 1\n"))
    assert one == []


def test_the_specification_rules_earn_no_advisory() -> None:
    for name in ("rule-google-secops-process-1.0.yaml", "rule-google-secops-spray-1.0.yaml"):
        document = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
        assert google_secops_advisories(document) == []


# --- the workspace checks ------------------------------------------------------------


def _named(title: str, name: str | None = None, enabled: bool = True) -> dict[str, Any]:
    block: dict[str, Any] = {"enabled": enabled, "status": "STAGING"}
    if name is not None:
        block["name"] = name
    return {"name": title, "metadata": {"uuid": "u"}, "configurations": {"google_secops": block}}


def test_rule_names_are_unique_case_insensitively() -> None:
    rules = {
        "a": _named("Password spray"),
        "b": _named("other", name="PASSWORD_SPRAY"),
        "c": _named("Password spray", enabled=False),
        "d": _named("Unique"),
    }
    issues = google_secops_name_issues(rules, ["a", "b", "c", "d"], lambda _uuid: None)
    assert [(issue.object_uuid, issue.code) for issue in issues] == [
        ("a", "google_secops_name_duplicate"),
        ("b", "google_secops_name_duplicate"),
    ]
    assert issues[0].field_path == ("configurations", "google_secops")


def test_a_section_alias_is_found(tmp_path: Path) -> None:
    text = (
        "name: x\n"
        "description: &shared |\n  $e\n"
        "configurations:\n"
        "  google_secops:\n"
        '    events: |\n      $e.metadata.event_type = "X"\n'
        "    condition: *shared\n"
    )
    assert aliased_sections(text) == ["condition"]
    path = tmp_path / "rule.yaml"
    path.write_text(text, encoding="utf-8")
    body = yaml.safe_load(text)
    issues = section_alias_issues(body, object_uuid="u", object_type="rule", file_path=path)
    assert [(i.code, i.field_path) for i in issues] == [
        ("yaral_section_alias", ("configurations", "google_secops", "condition"))
    ]
    assert aliased_sections("configurations: {google_secops: {events: x}}\n") == []
    assert aliased_sections(": [") == []
