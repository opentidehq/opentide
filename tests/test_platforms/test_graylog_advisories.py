"""Graylog advisories and the engine's leading-wildcard code (graylog-1.0, Advisories).

Advisories are warnings: validation reports them under their code and never
rejects the rule.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from opentide.analysis import Finding, _graylog_findings
from opentide.platforms.graylog.advisories import (
    ALL_STREAMS,
    OVERLAPPING_WINDOW,
    graylog_advisories,
    leading_wildcard_allowed,
    targeted_tenants,
)
from opentide.validation.graylog_advisories import graylog_advisory_issues
from opentide.validation.graylog_titles import graylog_title_issues


def _tenant(name: str = "prod", **setup: Any) -> SimpleNamespace:
    values = {"streams": ["sysmon"], "allow_leading_wildcard": False, **setup}
    return SimpleNamespace(name=name, setup=SimpleNamespace(**values))


def _rule(**block: Any) -> dict[str, Any]:
    return {
        "name": "Encoded PowerShell",
        "configurations": {
            "graylog": {"enabled": True, "status": "STAGING", "query": "EventID:1", **block}
        },
    }


def _codes(rule: dict[str, Any], tenants: list[Any] | None = None) -> list[str]:
    return [
        item.code for item in graylog_advisories(rule, [_tenant()] if tenants is None else tenants)
    ]


@pytest.mark.parametrize(
    ("block", "expected"),
    [
        ({"schedule": {"every": "5m", "window": "15m"}}, [OVERLAPPING_WINDOW]),
        ({"schedule": {"window": "10m"}}, [OVERLAPPING_WINDOW]),
        ({"schedule": {"every": "15m", "window": "15m"}}, []),
        ({"schedule": {"every": "15m", "window": "5m"}}, []),
        (
            {
                "schedule": {"every": "5m", "window": "15m"},
                "aggregation": {"condition": "count() > 1"},
            },
            [],
        ),
        ({"schedule": {"cron": "0 0 * * * ?", "window": "2h"}}, []),
        ({"schedule": {"every": "bad", "window": "15m"}}, []),
    ],
)
def test_overlapping_window(block: dict[str, Any], expected: list[str]) -> None:
    assert _codes(_rule(**block)) == expected


def test_an_overlapping_window_is_reported_at_the_schedule() -> None:
    (advisory,) = graylog_advisories(_rule(schedule={"window": "10m"}), [_tenant()])
    assert advisory.field_path == ("configurations", "graylog", "schedule")
    assert "10m" in advisory.message and "5m" in advisory.message


@pytest.mark.parametrize(
    ("block", "tenants", "expected"),
    [
        ({}, [_tenant()], []),
        ({}, [_tenant(streams=None)], [ALL_STREAMS]),
        ({}, [_tenant(), _tenant("lab", streams=[])], [ALL_STREAMS]),
        ({}, [], []),
        ({"streams": "sysmon"}, [_tenant(streams=None)], []),
        ({"stream_categories": ["edr"]}, [_tenant(streams=None)], []),
        ({"tenants": ["prod"]}, [_tenant(), _tenant("lab", streams=None)], []),
        ({"streams": ["a", "a"]}, [_tenant(streams=None)], []),
    ],
)
def test_all_streams(block: dict[str, Any], tenants: list[Any], expected: list[str]) -> None:
    assert _codes(_rule(**block), tenants) == expected


def test_all_streams_names_the_tenants_and_points_at_the_block() -> None:
    (advisory,) = graylog_advisories(_rule(), [_tenant("lab", streams=None)])
    assert advisory.field_path == ("configurations", "graylog")
    assert "lab" in advisory.message


def test_a_rule_without_a_graylog_block_has_none() -> None:
    assert graylog_advisories({"configurations": {"splunk": {}}}, []) == []
    assert graylog_advisories({}, []) == []


def test_targeted_tenants() -> None:
    tenants = [_tenant("prod"), _tenant("lab")]
    assert [t.name for t in targeted_tenants({}, tenants)] == ["prod", "lab"]
    assert [t.name for t in targeted_tenants({"tenants": ["lab"]}, tenants)] == ["lab"]


@pytest.mark.parametrize(
    ("tenants", "block", "allowed"),
    [
        ([], {}, False),
        ([_tenant(allow_leading_wildcard=True)], {}, True),
        ([_tenant(allow_leading_wildcard=True), _tenant("lab")], {}, False),
        (
            [_tenant(allow_leading_wildcard=True), _tenant("lab")],
            {"tenants": ["prod"]},
            True,
        ),
    ],
)
def test_leading_wildcard_allowed(tenants: list[Any], block: dict[str, Any], allowed: bool) -> None:
    assert leading_wildcard_allowed(block, tenants) is allowed


def _finding(code: str) -> Finding:
    return Finding(
        code=code,
        severity="error",
        message="m",
        line=1,
        column=1,
        end_line=1,
        end_column=2,
        field_path=("configurations", "graylog", "query"),
    )


_TEXT = "configurations:\n  graylog:\n    query: '*foo'\n"


def test_the_leading_wildcard_code_is_dropped_when_every_tenant_allows_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = (_finding("graylog_leading_wildcard"), _finding("lucene_parse_error"))
    monkeypatch.setattr(
        "opentide.platforms.graylog.advisories.configured_tenants",
        lambda: [_tenant(allow_leading_wildcard=True)],
    )
    assert [f.code for f in _graylog_findings(findings, _TEXT)] == ["lucene_parse_error"]
    monkeypatch.setattr(
        "opentide.platforms.graylog.advisories.configured_tenants",
        lambda: [_tenant(allow_leading_wildcard=True), _tenant("lab")],
    )
    assert _graylog_findings(findings, _TEXT) == findings
    monkeypatch.setattr("opentide.platforms.graylog.advisories.configured_tenants", list)
    assert _graylog_findings(findings, _TEXT) == findings, "offline, with no tenant, it stays"


def test_other_findings_pass_through_untouched() -> None:
    findings = (_finding("lucene_parse_error"),)
    assert _graylog_findings(findings, "not: [yaml") == findings
    leading = (_finding("graylog_leading_wildcard"),)
    assert _graylog_findings(leading, "not: [yaml") == leading


# --- validate ------------------------------------------------------------------------


def test_validate_reports_advisories_as_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "opentide.platforms.graylog.advisories.configured_tenants", lambda: [_tenant()]
    )
    (issue,) = graylog_advisory_issues(
        _rule(schedule={"window": "10m"}),
        object_uuid="u",
        object_type="rule",
        file_path=None,
    )
    assert (issue.code, issue.severity) == (OVERLAPPING_WINDOW, "warning")
    assert (
        graylog_advisory_issues(_rule(), object_uuid="u", object_type="threat", file_path=None)
        == []
    )
    assert graylog_advisory_issues({}, object_uuid="u", object_type="rule", file_path=None) == []


def test_two_enabled_blocks_with_one_title_warn() -> None:
    rules = {
        "a": _rule(),
        "b": _rule(),
        "c": _rule(name="Own title"),
        "d": {**_rule(), "configurations": {"graylog": {"enabled": False}}},
    }
    issues = graylog_title_issues(rules, ["a", "c", "d"], lambda uuid: Path(f"{uuid}.yaml"))
    assert [(issue.object_uuid, issue.code, issue.severity) for issue in issues] == [
        ("a", "graylog_title_duplicate", "warning")
    ]
    assert "b" in issues[0].message
    assert issues[0].field_path == ("configurations", "graylog")


def test_a_block_name_resolves_the_title() -> None:
    rules = {"a": _rule(name="Shared"), "b": {**_rule(name="Shared"), "name": "Other rule"}}
    assert len(graylog_title_issues(rules, ["a", "b"], lambda uuid: None)) == 2
