"""``opentide lint`` keeps the engine's platform advisories with the query warnings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from opentide import analysis
from opentide.analysis import ELASTIC_ADVISORY_CODES, SYSDIG_ADVISORY_CODES, Finding
from opentide.cli.services import explain
from opentide.cli.services.lint import _ObjectRecord, _query_findings


def _finding(code: str) -> Finding:
    return Finding(code, "warning", f"{code} here", 3, 5, 3, 9, ("configurations", "sysdig"))


@pytest.fixture
def engine_reports(monkeypatch: pytest.MonkeyPatch) -> list[Finding]:
    reported: list[Finding] = []
    monkeypatch.setattr(analysis, "install_workspace_visibility", lambda root: None)
    monkeypatch.setattr(analysis, "workspace", lambda root: object())
    monkeypatch.setattr(analysis, "check_file", lambda space, path, text, **_: list(reported))
    monkeypatch.setattr(
        "opentide.cli.ui.diagnostics.diagnostic_from_engine", lambda finding, **_: {}
    )
    return reported


def test_the_sysdig_advisory_is_a_lint_warning(
    tmp_path: Path, engine_reports: list[Finding]
) -> None:
    engine_reports.extend([_finding("sysdig_list_self_reference"), _finding("not_a_query_code")])
    record = _ObjectRecord(
        path=tmp_path / "rule.yaml", relative="objects/rules/rule.yaml", text="a\nb\nc\n"
    )
    found: list[dict[str, Any]] = _query_findings(tmp_path, [record])
    assert [(item["_code"], item["severity"]) for item in found] == [
        ("sysdig_list_self_reference", "warning")
    ]


def test_platform_advisory_sets_do_not_overlap() -> None:
    assert {"sysdig_list_self_reference"} == SYSDIG_ADVISORY_CODES
    assert not SYSDIG_ADVISORY_CODES & ELASTIC_ADVISORY_CODES


def test_the_sysdig_advisory_has_an_explain_page() -> None:
    page = explain.load_page("sysdig_list_self_reference")
    assert page is not None
    assert page.summary.startswith("A block list names itself")
    assert "## How to fix" in page.markdown


def test_an_engine_sysdig_advisory_without_a_page_says_where_it_shows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analysis, "describe", lambda code: "A sentence.")
    monkeypatch.setattr(analysis, "SYSDIG_ADVISORY_CODES", frozenset({"sysdig_new_advisory"}))
    page = explain.engine_page("sysdig_new_advisory")
    assert page is not None
    assert "Sysdig rule block (sysdig-1.0)" in page.markdown
    assert "opentide lint --check queries" in page.markdown


CROWDSTRIKE_WARNINGS = """\
name: CrowdStrike Warnings
metadata:
  uuid: 00000000-0000-4000-8003-000000000003
  schema: rule::1.0
configurations:
  crowdstrike:
    query: |
      #event_simpleName=ProcessRollup | groupBy(aid)
response:
  procedure:
    searches:
      - system: crowdstrike
        query: '#event_simpleName=DnsReques | groupBy(aid)'
"""


def test_lint_reports_cql_warnings(tmp_path: Path) -> None:
    """lint reports the CQL warnings of a rule's block and of a hunt, as the editor does.

    Until CrowdStrike became an offline platform, lint dropped them as the
    editor's only; that was the intended behaviour then and this asserts the new one.
    """
    rule = tmp_path / "crowdstrike-warnings.yaml"
    rule.write_text(CROWDSTRIKE_WARNINGS, encoding="utf-8")
    editor = analysis.check_file(analysis.workspace(tmp_path), rule, CROWDSTRIKE_WARNINGS)
    warned = [finding for finding in editor if finding.code.startswith("cql_")]
    assert {finding.field_path[0] for finding in warned} == {"configurations", "response"}
    assert {finding.severity for finding in warned} == {"warning"}
    record = _ObjectRecord(path=rule, relative=rule.name, text=CROWDSTRIKE_WARNINGS)
    found = _query_findings(tmp_path, [record])
    cql = [item for item in found if str(item["_code"]).startswith("cql_")]
    assert sorted((item["_code"], item["severity"]) for item in cql) == sorted(
        (finding.code, "warning") for finding in warned
    )


def test_a_cql_code_has_a_page_that_names_validate_and_lint() -> None:
    page = explain.load_page("cql_unknown_function")
    assert page is not None
    assert "CQL query" in page.markdown
    assert "opentide validate query" in page.markdown
    assert "https://library.humio.com/crowdstrike-query-language/" in page.markdown
