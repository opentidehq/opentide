"""Google SecOps rule assembly against the specification goldens (google-secops-1.0).

``tests/fixtures/google_secops/`` is a copy of the specification's
``fixtures/platforms/google-secops/`` and the two ``rule-google-secops-*``
rules: each ``.yaral`` is the text deploy assembles, byte for byte.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.google_secops.compile import (
    assemble,
    meta_entries,
    meta_value,
    rule_name,
    run_state,
    severity,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "google_secops"
RULES = {
    "rule-google-secops-process-1.0": StatusStrategy.PREVIEW,
    "rule-google-secops-spray-1.0": StatusStrategy.RELEASE,
}


def load_fixture_rule(stem: str, **block: Any) -> DetectionRule:
    """A specification rule fixture, loaded as opentide loads a rule."""
    document = yaml.safe_load((FIXTURES / f"{stem}.yaml").read_text(encoding="utf-8"))
    document["configurations"]["google_secops"].update(block)
    return load_rule_from_dict(document)


def _golden(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("stem", sorted(RULES))
def test_the_assembled_text_is_the_golden_byte_for_byte(stem: str) -> None:
    expected = (FIXTURES / f"{stem}.yaral").read_bytes().decode("utf-8")
    assert assemble(load_fixture_rule(stem)).text == expected


@pytest.mark.parametrize("stem", sorted(RULES))
def test_the_verify_and_create_bodies_are_the_goldens(stem: str) -> None:
    text = assemble(load_fixture_rule(stem)).text
    assert _golden(f"{stem}.verify.api.json")["body"] == {"ruleText": text}
    assert _golden(f"{stem}.create.api.json")["body"] == {"text": text}


@pytest.mark.parametrize(("stem", "strategy"), sorted(RULES.items()))
def test_the_run_state_is_the_golden(stem: str, strategy: StatusStrategy) -> None:
    rule = load_fixture_rule(stem)
    block = rule.platform_configs().google_secops
    assert block is not None
    state = run_state(block, strategy)
    golden = _golden(f"{stem}.deployment.api.json")
    assert {"updateMask": state.mask} == golden["query"]
    assert dict(state.body) == golden["body"]
    disabled = run_state(block, StatusStrategy.DISABLEMENT)
    assert {"updateMask": disabled.mask} == _golden(f"{stem}.disable.api.json")["query"]
    assert dict(disabled.body) == _golden(f"{stem}.disable.api.json")["body"]


def test_the_rule_name() -> None:
    process = load_fixture_rule("rule-google-secops-process-1.0")
    assert assemble(process).name == "office_application_spawns_encoded_powershell"
    assert rule_name("2FA bypass!", None, "u") == "r_2fa_bypass"
    assert rule_name("!!!", None, "0000-11") == "opentide_0000_11"
    assert rule_name("anything", "explicit_name", "u") == "explicit_name"
    assert assemble(load_fixture_rule("rule-google-secops-spray-1.0")).name == (
        "password_spray_then_success"
    )


def test_the_meta_derivations() -> None:
    process = dict(meta_entries(*_rule_and_block("rule-google-secops-process-1.0")))
    assert process["author"] == "Detection Engineering, Threat Hunting"
    assert "tactic" not in process
    assert process["technique"] == "T1059.001,T1566.001"
    assert list(process)[-1] == "data_source"
    spray = dict(meta_entries(*_rule_and_block("rule-google-secops-spray-1.0")))
    assert spray["technique"] == "T1078,T1110.003"
    assert spray["severity"] == spray["priority"] == "High"


def _rule_and_block(stem: str, **block: Any) -> tuple[DetectionRule, Any]:
    rule = load_fixture_rule(stem, **block)
    config = rule.platform_configs().google_secops
    assert config is not None
    return rule, config


def test_meta_values_are_yaral_strings() -> None:
    assert meta_value('a "b"\\c\nd\te') == '"a \\"b\\"\\\\c d e"'


@pytest.mark.parametrize(
    ("alert_severity", "expected"),
    [("Informational", "Info"), ("Low", "Low"), ("Critical", "Critical"), (None, "Medium")],
)
def test_the_severity_follows_the_alert_severity(alert_severity: str | None, expected: str) -> None:
    document = yaml.safe_load(
        (FIXTURES / "rule-google-secops-process-1.0.yaml").read_text(encoding="utf-8")
    )
    if alert_severity is None:
        del document["response"]
    else:
        document["response"]["alert_severity"] = alert_severity
    rule = load_rule_from_dict(document)
    block = rule.platform_configs().google_secops
    assert block is not None
    assert severity(rule, block) == expected


def test_the_block_severity_and_priority_win() -> None:
    rule, block = _rule_and_block(
        "rule-google-secops-process-1.0", severity="Low", priority="Critical"
    )
    entries = dict(meta_entries(rule, block))
    assert (entries["severity"], entries["priority"]) == ("Low", "Critical")


def test_sections_are_trimmed_indented_and_mapped_back() -> None:
    rule, _ = _rule_and_block(
        "rule-google-secops-process-1.0",
        events='\r\n\r\n$e.metadata.event_type = "X"\r\n\r\n  $e.principal.hostname = "h"\r\n\r\n',
        match={"group_by": ["$h"], "window": "5m", "type": "sliding", "pivot": "$e"}
        | {"direction": "before"},
        options={"suppression_window": "1h", "allow_zero_values": True},
        setup="graph_override($g.graph.entity.hostname = $e.principal.hostname)\n",
        export="%table.write_row(host: $host)\n",
    )
    assembled = assemble(rule)
    lines = assembled.text.split("\n")
    order = [place.key for place in assembled.sections]
    assert order == ["setup", "events", "match", "outcome", "condition", "options", "export"]
    events = assembled.label_line("events")
    assert events is not None
    assert lines[events - 1] == "  events:"
    assert lines[events] == '    $e.metadata.event_type = "X"'
    assert lines[events + 1] == ""
    assert lines[events + 2] == '      $e.principal.hostname = "h"'
    assert "    $h over 5m before $e" in lines
    assert "    allow_zero_values = true" in lines
    assert lines.index("    allow_zero_values = true") < lines.index("    suppression_window = 1h")
    # Line 5 of the text as written (two blank lines dropped) is its line 3 written out.
    located = assembled.locate(events + 3, 7)
    assert (located.key, located.line, located.column) == ("events", 5, 3)
    match_line = assembled.label_line("match")
    assert match_line is not None
    assert assembled.locate(match_line + 1, 5).key == "match"
    assert assembled.locate(2, 1).key is None
    assert assembled.locate(None).describe() == "configurations.google_secops"


def test_tumbling_window_renders_by() -> None:
    rule, _ = _rule_and_block(
        "rule-google-secops-process-1.0",
        match={"group_by": ["$h"], "window": "1h"} | {"type": "tumbling"},
    )
    assert "    $h by 1h\n" in assemble(rule).text


def test_alerting_and_no_frequency_unless_the_block_names_one() -> None:
    _, block = _rule_and_block("rule-google-secops-process-1.0", alerting=True, run_frequency=None)
    state = run_state(block, StatusStrategy.PREVIEW)
    assert state.mask == "enabled,alerting"
    assert dict(state.body) == {"enabled": True, "alerting": True}


def test_the_run_state_compares_with_the_remote() -> None:
    _, block = _rule_and_block("rule-google-secops-spray-1.0")
    state = run_state(block, StatusStrategy.RELEASE)
    same = {
        "enabled": True,
        "alerting": True,
        "runFrequency": "LIVE_CUSTOMIZABLE",
        "scheduleCustomizations": {
            "ensureEnrichmentCompleteness": True,
            "lateArrivingDataAdjustment": "1800s",
        },
    }
    assert not state.differs_from(same)
    assert state.differs_from({**same, "alerting": False})
    assert state.differs_from({**same, "scheduleCustomizations": {}})
    disabled = run_state(block, StatusStrategy.DISABLEMENT)
    # Google leaves false booleans out of its answer.
    assert not disabled.differs_from({})
    # A Duration in another spelling is the same number of seconds.
    stored = {"lateArrivingDataAdjustment": "1800.000s", "ensureEnrichmentCompleteness": True}
    assert not state.differs_from({**same, "scheduleCustomizations": stored})
    changes = state.changes({**same, "enabled": False})
    assert changes is not None
    assert (changes.mask, dict(changes.body)) == ("enabled", {"enabled": True})


def test_a_false_schedule_boolean_settles_against_an_absent_one() -> None:
    _, block = _rule_and_block(
        "rule-google-secops-spray-1.0",
        schedule={"ensure_enrichment_completeness": False},
    )
    state = run_state(block, StatusStrategy.RELEASE)
    remote = {"enabled": True, "alerting": True, "runFrequency": "LIVE_CUSTOMIZABLE"}
    assert not state.differs_from(remote)
    assert not state.differs_from({**remote, "scheduleCustomizations": {}})


def test_a_removed_schedule_wants_the_remote_one_cleared() -> None:
    _, block = _rule_and_block("rule-google-secops-spray-1.0", schedule=None)
    state = run_state(block, StatusStrategy.RELEASE)
    remote = {
        "enabled": True,
        "alerting": True,
        "runFrequency": "LIVE_CUSTOMIZABLE",
        "scheduleCustomizations": {"ensureEnrichmentCompleteness": True},
    }
    changes = state.changes(remote)
    assert changes is not None
    assert (changes.mask, dict(changes.body)) == (
        "runFrequency",
        {"runFrequency": "LIVE_CUSTOMIZABLE"},
    )
