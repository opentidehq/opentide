"""Bitdefender advisories: warnings from validate and lint, never a rejection (bitdefender-1.0)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from opentide.cli.services import explain
from opentide.cli.services.lint import _bitdefender_findings, _ObjectRecord
from opentide.platforms.bitdefender.advisories import (
    ADVISORY_CODES,
    CONTAINS_NO_WILDCARD,
    REGISTRY_FULL_HIVE,
    SEVERITY_COLLAPSED,
    bitdefender_advisories,
)
from opentide.validation.bitdefender_advisories import bitdefender_advisory_issues


def _rule(*criteria: dict[str, Any], severity: str | None = None, **rule: Any) -> dict[str, Any]:
    block: dict[str, Any] = {
        "status": "STAGING",
        "detection": {"target": "registry", "criteria": list(criteria)},
    }
    if severity is not None:
        block["severity"] = severity
    return {"name": "R", "configurations": {"bitdefender": block}, **rule}


def _codes(rule: dict[str, Any]) -> list[str]:
    return [advisory.code for advisory in bitdefender_advisories(rule)]


@pytest.mark.parametrize(
    "criterion",
    [
        {"field": "Registry.Key", "is": "HKEY_LOCAL_MACHINE\\Software\\Run"},
        {"field": "Registry.Key", "contains": "hkey_current_user\\Software*"},
        {"field": "Registry.Key", "any": ["HKLM\\Run", "HKEY_USERS\\x"]},
    ],
)
def test_a_full_hive_name_is_an_advisory(criterion: dict[str, Any]) -> None:
    assert REGISTRY_FULL_HIVE in _codes(_rule(criterion))


def test_a_short_hive_name_is_not() -> None:
    assert _codes(_rule({"field": "Registry.Key", "contains": "HKLM\\Software\\*"})) == []


def test_contains_without_a_wildcard_is_an_advisory() -> None:
    advisories = bitdefender_advisories(_rule({"field": "Registry.Value", "contains": "Run"}))
    assert [a.code for a in advisories] == [CONTAINS_NO_WILDCARD]
    assert advisories[0].field_path == (
        "configurations",
        "bitdefender",
        "detection",
        "criteria",
        "0",
        "contains",
    )
    for value in ("*Run*", "Ru?"):
        assert _codes(_rule({"field": "Registry.Value", "contains": value})) == []


@pytest.mark.parametrize(
    ("alert_severity", "severity", "expected"),
    [
        ("Critical", None, [SEVERITY_COLLAPSED]),
        ("Informational", None, [SEVERITY_COLLAPSED]),
        ("Critical", "High", []),
        ("High", None, []),
    ],
)
def test_a_collapsed_severity_is_an_advisory(
    alert_severity: str, severity: str | None, expected: list[str]
) -> None:
    rule = _rule(severity=severity, response={"alert_severity": alert_severity})
    assert _codes(rule) == expected


def test_a_rule_without_a_bitdefender_block_has_none() -> None:
    assert bitdefender_advisories({"name": "R", "configurations": {"sysdig": {}}}) == []
    assert bitdefender_advisories({"name": "R"}) == []


def test_validate_reports_advisories_as_warnings() -> None:
    issues = bitdefender_advisory_issues(
        _rule({"field": "Registry.Value", "contains": "Run"}),
        object_uuid="u",
        object_type="rule",
        file_path=None,
    )
    assert [(issue.code, issue.severity) for issue in issues] == [(CONTAINS_NO_WILDCARD, "warning")]
    assert (
        bitdefender_advisory_issues({}, object_uuid="u", object_type="threat", file_path=None) == []
    )


def test_lint_reports_advisories_at_their_line(tmp_path: Path) -> None:
    text = (
        "name: R\n"
        "response:\n"
        "  alert_severity: Critical\n"
        "configurations:\n"
        "  bitdefender:\n"
        "    status: STAGING\n"
        "    detection:\n"
        "      target: registry\n"
        "      criteria:\n"
        "        - field: Registry.Key\n"
        "          is: HKEY_LOCAL_MACHINE\\Run\n"
    )
    path = tmp_path / "rule.yaml"
    path.write_text(text, encoding="utf-8")
    record = _ObjectRecord(path=path, relative="objects/rules/rule.yaml", text=text)
    found = _bitdefender_findings([record])
    assert {(item["_code"], item["severity"], item["yaml_line"]) for item in found} == {
        (SEVERITY_COLLAPSED, "warning", 2),
        (REGISTRY_FULL_HIVE, "warning", 10),
    }
    assert all(item["check"] == "queries" for item in found)


@pytest.mark.parametrize("code", sorted(ADVISORY_CODES))
def test_every_advisory_has_an_explain_page(code: str) -> None:
    page = explain.load_page(code)
    assert page is not None
    assert "## How to fix" in page.markdown
