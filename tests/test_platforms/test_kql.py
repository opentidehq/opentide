"""KQL query compilation with tenant exclusions."""

from __future__ import annotations

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
