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
    monkeypatch.setattr(analysis, "check_file", lambda space, path, text: list(reported))
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
