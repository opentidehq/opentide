"""CLI info service behaviour."""

from __future__ import annotations

from io import StringIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from opentide.cli.context import CliContext
from opentide.cli.enums import DetectionPlatform
from opentide.cli.services import info as info_service


def test_collect_info_default_payload() -> None:
    ctx = CliContext(json_output=True)
    platform = MagicMock(enabled=True, can_deploy=True, can_validate=False)
    with patch.object(info_service, "OpenTide") as mock_ot:
        mock_ot.initialise.return_value = None
        mock_ot.Platforms.items.return_value = [("sentinel", platform)]
        mock_ot.Models.rules = {"r1": MagicMock()}
        mock_ot.Models.threats = {}
        mock_ot.Models.objectives = {}
        payload = info_service.collect_info(ctx)
    assert payload["counts"]["rules"] == 1
    assert payload["platforms"][0]["name"] == "sentinel"


def test_collect_info_filters_platform() -> None:
    ctx = CliContext(json_output=True)
    platform = MagicMock(enabled=True, can_deploy=True, can_validate=True)
    with patch.object(info_service, "OpenTide") as mock_ot:
        mock_ot.initialise.return_value = None
        mock_ot.Platforms.items.return_value = [
            ("sentinel", platform),
            ("splunk", platform),
        ]
        mock_ot.Models.rules = {}
        mock_ot.Models.threats = {}
        mock_ot.Models.objectives = {}
        payload = info_service.collect_info(ctx, platform=DetectionPlatform.sentinel)
    assert len(payload["platforms"]) == 1


def test_collect_info_rules_section() -> None:
    ctx = CliContext(json_output=True)
    with patch.object(info_service, "OpenTide") as mock_ot:
        mock_ot.initialise.return_value = None
        mock_ot.Platforms.items.return_value = []
        mock_ot.Models.rules = {"r1": MagicMock(), "r2": MagicMock()}
        mock_ot.Models.threats = {}
        mock_ot.Models.objectives = {}
        payload = info_service.collect_info(ctx, section="rules")
    assert payload["rules"] == ["r1", "r2"]


def test_collect_info_threats_and_objectives_sections() -> None:
    ctx = CliContext(json_output=True)
    with patch.object(info_service, "OpenTide") as mock_ot:
        mock_ot.initialise.return_value = None
        mock_ot.Platforms.items.return_value = []
        mock_ot.Models.rules = {}
        mock_ot.Models.threats = {"t1": MagicMock()}
        mock_ot.Models.objectives = {"o1": MagicMock()}
        threats = info_service.collect_info(ctx, section="threats")
        objectives = info_service.collect_info(ctx, section="objectives")
    assert threats["threats"] == ["t1"]
    assert objectives["objectives"] == ["o1"]


def test_collect_info_coverage_section() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch.object(info_service, "OpenTide") as mock_ot,
        patch.object(info_service, "_technique_coverage", return_value={"count": 0}),
    ):
        mock_ot.initialise.return_value = None
        mock_ot.Platforms.items.return_value = []
        mock_ot.Models.rules = {}
        mock_ot.Models.threats = {}
        mock_ot.Models.objectives = {}
        payload = info_service.collect_info(ctx, section="coverage", technique="T1059")
    assert payload["coverage"]["count"] == 0


def test_technique_coverage_matches_rules() -> None:
    rule = MagicMock()
    rule.model_dump.return_value = {"tags": {"techniques": ["T1059", "T1003"]}}
    with patch.object(info_service, "OpenTide") as mock_ot:
        mock_ot.Models.rules = {"u1": rule}
        coverage = info_service._technique_coverage("T1059")
    assert coverage["count"] == 1
    assert coverage["rules"] == ["u1"]


def test_technique_coverage_accepts_dict_rules() -> None:
    with patch.object(info_service, "OpenTide") as mock_ot:
        mock_ot.Models.rules = {
            "u2": {"tags": {"attack": ["T1003"]}},
        }
        coverage = info_service._technique_coverage("T1003")
    assert coverage["count"] == 1


def test_technique_coverage_matches_top_level_techniques() -> None:
    with patch.object(info_service, "OpenTide") as mock_ot:
        mock_ot.Models.rules = {
            "u3": {"techniques": ["T1059"], "tags": {}},
        }
        coverage = info_service._technique_coverage("T1059")
    assert coverage["count"] == 1
    assert coverage["rules"] == ["u3"]


def test_package_version_helper() -> None:
    assert info_service._package_version()


_SUMMARY: dict[str, Any] = {
    "version": "0.0.0",
    "counts": {"rules": 1, "threats": 1, "objectives": 1},
    "platforms": [
        {"name": "sentinel", "enabled": True, "can_deploy": True, "can_validate": True},
        {"name": "crowdstrike", "enabled": False, "can_deploy": True, "can_validate": False},
    ],
}

_OBJECTS = {
    "rules": {"r-1": {"name": "Encoded [PowerShell]", "configurations": {"sentinel": {}}}},
    "threats": {"t-1": {"name": "Simulated [actor]"}},
    "objectives": {"o-1": {"name": "Credential access"}},
}


def _render(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], section: str | None = None
) -> str:
    buffer = StringIO()
    console = Console(file=buffer, width=200, force_terminal=False, no_color=True)
    monkeypatch.setattr(info_service, "get_stdout_console", lambda: console)
    with patch.object(info_service, "OpenTide") as mock_ot:
        for family, objects in _OBJECTS.items():
            setattr(mock_ot.Models, family, objects)
        info_service.render_info(payload, section=section)
    return buffer.getvalue()


def test_render_info_summary_keeps_the_capability_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rich read `[deploy, validate]` as a markup tag and printed nothing (#292)."""
    output = _render(monkeypatch, _SUMMARY)
    assert "enabled=True [deploy, validate]" in output
    assert "enabled=False [deploy]" in output


@pytest.mark.parametrize(
    ("section", "uuid", "name"),
    [
        ("rules", "r-1", "Encoded [PowerShell]"),
        ("threats", "t-1", "Simulated [actor]"),
        ("objectives", "o-1", "Credential access"),
    ],
)
def test_render_info_section_lists_its_objects(
    monkeypatch: pytest.MonkeyPatch, section: str, uuid: str, name: str
) -> None:
    """Human `info <section>` printed the summary table instead (#293)."""
    output = _render(monkeypatch, {**_SUMMARY, section: [uuid]}, section)
    assert uuid in output
    assert name in output
    assert "OpenTide Info" not in output


def test_render_info_rules_section_names_rule_platforms(monkeypatch: pytest.MonkeyPatch) -> None:
    output = _render(monkeypatch, {**_SUMMARY, "rules": ["r-1"]}, "rules")
    row = next(line for line in output.splitlines() if "r-1" in line)
    assert "sentinel" in row


def test_render_info_empty_section_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    assert "No threats found" in _render(monkeypatch, {**_SUMMARY, "threats": []}, "threats")


@pytest.mark.parametrize(("rules", "summary"), [(["r-1"], "1 rule"), ([], "0 rules")])
def test_render_info_coverage_shows_technique_count_and_rules(
    monkeypatch: pytest.MonkeyPatch, rules: list[str], summary: str
) -> None:
    coverage = {"technique": "T1059", "rules": rules, "count": len(rules)}
    output = _render(monkeypatch, {**_SUMMARY, "coverage": coverage}, "coverage")
    assert f"Coverage for T1059: {summary}" in output
    assert ("r-1" in output) is bool(rules)
    assert "OpenTide Info" not in output
