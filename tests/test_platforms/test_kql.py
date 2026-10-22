"""KQL query compilation with tenant exclusions."""

from __future__ import annotations

import pytest

from opentide.models.platform_configs import DefenderExclusion, SentinelExclusion
from opentide.platforms.kql import compile_kql_query


def test_compile_kql_query_no_exclusions() -> None:
    assert compile_kql_query("DeviceEvents | take 1", None, "tenant-a") == "DeviceEvents | take 1"


def test_compile_kql_query_applies_matching_tenant_exclusion() -> None:
    exclusions = [
        SentinelExclusion(
            query="| where DeviceName !contains 'test'",
            reason="noise",
            tenant="tenant-a",
            let={"host": "server1"},
        )
    ]
    result = compile_kql_query("DeviceEvents", exclusions, "tenant-a")
    assert "let host" in result
    assert '"server1"' in result
    assert "DeviceEvents" in result
    assert "DeviceName !contains" in result


def test_compile_kql_query_skips_other_tenant() -> None:
    exclusions = [
        DefenderExclusion(
            query="| where AccountName != 'admin'",
            reason="exclude",
            tenant="other-tenant",
        )
    ]
    result = compile_kql_query("SecurityAlert", exclusions, "tenant-a")
    assert result == "SecurityAlert"


def test_compile_kql_query_global_exclusion_without_tenant() -> None:
    exclusions = [
        DefenderExclusion(
            query="| where Severity != 'Informational'",
            reason="global",
            tenant=None,
            let={"enabled": True, "threshold": 5, "label": "high"},
        )
    ]
    result = compile_kql_query("AlertInfo", exclusions, "any")
    assert "let enabled = true;" in result
    assert "let threshold = 5;" in result
    assert 'let label = "high";' in result
    assert "Severity != 'Informational'" in result


@pytest.mark.parametrize(
    ("value", "literal"),
    [
        ("C:\\Windows\\Temp\\", '"C:\\\\Windows\\\\Temp\\\\"'),
        ("C:\\temp", '"C:\\\\temp"'),
        ('say "hi"', '"say \\"hi\\""'),
        ("two\nlines\tand\rmore", '"two\\nlines\\tand\\rmore"'),
        ("plain", '"plain"'),
    ],
    ids=["trailing-backslash", "backslash-t", "double-quote", "control-characters", "plain"],
)
def test_let_string_values_are_escaped(value: str, literal: str) -> None:
    """Values went into the literal as they were.

    ``C:\\Windows\\Temp\\`` escaped the closing quote and broke the query;
    ``C:\\temp`` matched a tab.
    """
    exclusions = [SentinelExclusion(query="| where true", reason="paths", let={"path": value})]
    result = compile_kql_query("Table", exclusions, "tenant-a")
    assert result.splitlines()[0] == f"let path = {literal};"


def test_compile_kql_query_skips_unsupported_let_types() -> None:
    exclusions = [
        SentinelExclusion(
            query="| where true",
            reason="bad let",
            let={"items": ["nested"]},
        )
    ]
    result = compile_kql_query("Table", exclusions, "tenant-a")
    assert "let items" not in result
    assert "| where true" in result
