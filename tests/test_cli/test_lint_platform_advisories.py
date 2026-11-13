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


_SIGNATURE_FILE = (
    "name: x\nconfigurations:\n  harfanglab:\n    yara:\n      signature: |\n"
    '        rule a {\n          meta:\n            context = "disk"\n'
    "          condition:\n            true\n        }\n"
    '        rule b {\n          meta:\n            context = "file"\n'
    "          condition:\n            true\n        }\n"
)


def _engine(code: str, line: int) -> Finding:
    """An engine advisory at 1-based *line*."""
    return Finding(code, "warning", f"{code} here", line, 9, line, 20, ("configurations",))


def test_the_engine_copy_of_an_advisory_opentide_reports_is_dropped(
    tmp_path: Path, engine_reports: list[Finding]
) -> None:
    """One finding per code, form and YARA rule: opentide's, placed on its own line."""
    engine_reports.append(_engine("harfanglab_yara_context", 8))  # rule a, which opentide finds
    record = _ObjectRecord(
        path=tmp_path / "rule.yaml", relative="objects/rules/rule.yaml", text=_SIGNATURE_FILE
    )
    assert _query_findings(tmp_path, [record]) == []


def test_an_advisory_only_the_engine_reports_is_kept(
    tmp_path: Path, engine_reports: list[Finding]
) -> None:
    """The engine's finding on rule b, which opentide's check passes, is never dropped."""
    engine_reports.append(_engine("harfanglab_yara_context", 14))  # rule b
    engine_reports.append(_engine("yara_meta_missing", 6))  # rule a: a code opentide did not find
    record = _ObjectRecord(
        path=tmp_path / "rule.yaml", relative="objects/rules/rule.yaml", text=_SIGNATURE_FILE
    )
    found = _query_findings(tmp_path, [record])
    assert sorted((item["_code"], item["yaml_line"]) for item in found) == [
        ("harfanglab_yara_context", 13),
        ("yara_meta_missing", 5),
    ]


def test_a_decomposed_advisory_is_keyed_by_form(
    tmp_path: Path, engine_reports: list[Finding]
) -> None:
    decomposed = (
        "name: x\nconfigurations:\n  harfanglab:\n    yara:\n"
        "      meta:\n        context: []\n        os: Windows\n"
        '      strings: |\n        $a = "x"\n      condition: |\n        $a\n'
    )
    record = _ObjectRecord(
        path=tmp_path / "rule.yaml", relative="objects/rules/rule.yaml", text=decomposed
    )
    engine_reports.append(_engine("yara_meta_missing", 1))  # the engine's, on the rule name
    assert _query_findings(tmp_path, [record]) == []
    engine_reports[:] = [_engine("harfanglab_yara_context", 1)]  # a code opentide did not find
    assert [item["_code"] for item in _query_findings(tmp_path, [record])] == [
        "harfanglab_yara_context"
    ]


_EXABEAM_FILE = (
    "name: x\nconfigurations:\n  exabeam:\n    status: STAGING\n    outcome: none\n"
    "    sequences:\n      - query: a\n        threshold: {within: 1h}\n      - query: b\n"
    "    correlation:\n      within: 15m\n"
)


def test_the_exabeam_advisories_are_lint_warnings_at_their_key(tmp_path: Path) -> None:
    """Reported with no engine: they are opentide's own (exabeam-1.0, Advisories)."""
    from opentide.cli.services.lint import _exabeam_findings

    path = tmp_path / "rule.yaml"
    path.write_text(_EXABEAM_FILE, encoding="utf-8")
    record = _ObjectRecord(path=path, relative="objects/rules/rule.yaml", text=_EXABEAM_FILE)
    found = _exabeam_findings([record])
    assert [(item["_code"], item["severity"], item["_field_path"]) for item in found] == [
        ("exabeam_outcome_silent", "warning", ["configurations", "exabeam", "outcome"]),
        (
            "exabeam_correlation_window",
            "warning",
            ["configurations", "exabeam", "correlation", "within"],
        ),
    ]
    # A file that does not name the platform, or does not parse, is not read.
    other = _ObjectRecord(path=path, relative="r.yaml", text="name: x\n")
    broken = _ObjectRecord(path=path, relative="r.yaml", text="exabeam: [\n")
    assert _exabeam_findings([other, broken]) == []
