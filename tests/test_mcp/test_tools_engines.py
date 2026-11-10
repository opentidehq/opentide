"""The MCP validation tools and the SDK's ``run_validation`` on each engine (#822).

``OPENTIDE_ENGINE=rust`` validates on the Rust workspace; the Python
implementation is the oracle, and each tool result must be the same on both.
``compare`` is shadow mode: the Python result, with any difference logged
and written to a diff report.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import CORPUS_OBJECTIVE_UUID, CORPUS_RULE_UUIDS, clear_runtime_caches

from opentide.mcp_server import tools
from opentide.validation import engine as validation_engine

_RULE = "objects/rules/rule-0001-sentinel-kql.yaml"
_UUID = CORPUS_RULE_UUIDS["sentinel"]
MISSING_UUID = "00000000-0000-4000-8fff-0000000000ff"


def _edit(old: str, new: str) -> Callable[[Path], None]:
    def apply(repo: Path) -> None:
        path = repo / _RULE
        text = path.read_text(encoding="utf-8")
        assert old in text
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    return apply


#: Workspaces the tools are compared on: the corpus, and one broken rule each.
EDITS: dict[str, Callable[[Path], None]] = {
    "clean": lambda _: None,
    "vocab-typo": _edit("  tlp: clear\n", "  tlp: clearr\n"),
    "safe-fix": _edit("  tlp: clear\n", "  tlp: Clear\n"),
    "dangling-ref": _edit(
        f"detection_model: {CORPUS_OBJECTIVE_UUID}", f"detection_model: {MISSING_UUID}"
    ),
}

#: An approved difference (``unknown-revision``, tests/golden/APPROVED_DIFFS.toml,
#: #813): Rust checks a rule of an unknown revision against the newest one and
#: says so in the message; codes, fields and places are the same.
UNKNOWN_SCHEMA = _edit("schema: rule::1.0", "schema: rule::9.9")

#: The tool calls compared.
CALLS: dict[str, Callable[[], dict[str, Any]]] = {
    "report": lambda: tools.tool_validation_report(),
    "report-warn": lambda: tools.tool_validation_report(queries="warn"),
    "report-off": lambda: tools.tool_validation_report(queries="off"),
    "report-file": lambda: tools.tool_validation_report(file=_RULE),
    "report-uuid": lambda: tools.tool_validation_report(uuid=_UUID),
    "report-type": lambda: tools.tool_validation_report(object_type="rule"),
    "rule": lambda: tools.tool_validate_rule(_UUID),
    "rule-missing": lambda: tools.tool_validate_rule(MISSING_UUID),
}


def _without_timing(payload: dict[str, Any]) -> dict[str, Any]:
    stats = payload.get("stats")
    if isinstance(stats, dict):
        payload = {**payload, "stats": {k: v for k, v in stats.items() if k != "wall_ms"}}
    return payload


def _call(name: str, engine: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("OPENTIDE_ENGINE", engine)
    clear_runtime_caches()
    return _without_timing(CALLS[name]())


@pytest.fixture
def rust_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """The Rust runs the tools made."""
    seen: list[dict[str, Any]] = []
    real = validation_engine.run_rust

    def counting(request: validation_engine.RustRequest) -> dict[str, Any]:
        seen.append({"files": request.files, "uuids": request.uuids, "queries": request.queries})
        return real(request)

    monkeypatch.setattr(validation_engine, "run_rust", counting)
    return seen


@pytest.mark.parametrize("edit", list(EDITS))
@pytest.mark.parametrize("call", list(CALLS))
def test_the_tools_answer_the_same_on_rust(
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    rust_calls: list[dict[str, Any]],
    edit: str,
    call: str,
) -> None:
    EDITS[edit](tide_corpus_repo)
    python = _call(call, "python", monkeypatch)
    assert rust_calls == []
    rust = _call(call, "rust", monkeypatch)
    assert rust == python
    # Key order is part of the payload an agent reads.
    assert json.dumps(rust) == json.dumps(python)
    assert len(rust_calls) == (0 if call == "rule-missing" else 1)


@pytest.mark.parametrize("call", ["report", "rule"])
def test_an_unknown_revision_differs_only_as_approved(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch, call: str
) -> None:
    UNKNOWN_SCHEMA(tide_corpus_repo)
    python = _call(call, "python", monkeypatch)
    rust = _call(call, "rust", monkeypatch)
    worded = "unknown schema identifier: 'rule::9.9'"
    approved = f"{worded}; checked against rule::1.1, the newest rule revision"

    def approve(payload: dict[str, Any]) -> dict[str, Any]:
        """The payload with the identifier's message as Python words it."""
        text = json.dumps(payload)
        while (start := text.find("Value error, " + approved)) >= 0:
            end = text.index('"', start)
            text = text[:start] + worded + text[end:]
        return json.loads(text)

    assert rust != python
    assert approved in json.dumps(rust)
    assert approve(rust) == python


def test_the_rust_request_carries_the_scope(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch, rust_calls: list[dict[str, Any]]
) -> None:
    monkeypatch.setenv("OPENTIDE_ENGINE", "rust")
    tools.tool_validation_report(file=_RULE, queries="warn")
    tools.tool_validate_rule(_UUID)
    assert rust_calls == [
        {"files": (_RULE,), "uuids": (), "queries": "warn"},
        {"files": (), "uuids": (_UUID,), "queries": "error"},
    ]


def _state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(home))
    monkeypatch.setattr("sys.platform", "linux")
    return home / "opentide" / "compare"


def test_compare_returns_python_and_writes_no_report_when_both_agree(
    tide_corpus_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _state(tmp_path, monkeypatch)
    EDITS["vocab-typo"](tide_corpus_repo)
    python = _call("report", "python", monkeypatch)
    compared = _call("report", "compare", monkeypatch)
    assert compared == python
    assert not reports.exists()


def test_compare_records_a_difference_and_still_answers_with_python(
    tide_corpus_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _state(tmp_path, monkeypatch)
    EDITS["vocab-typo"](tide_corpus_repo)
    python = _call("report", "python", monkeypatch)
    real = validation_engine.run_rust

    def divergent(request: validation_engine.RustRequest) -> dict[str, Any]:
        result = real(request)
        result["report"]["issues"][0]["message"] = "a different message"
        return result

    monkeypatch.setattr(validation_engine, "run_rust", divergent)
    compared = _call("report", "compare", monkeypatch)
    assert compared == python
    written = list(reports.glob("*.json"))
    assert len(written) == 1
    report = json.loads(written[0].read_text(encoding="utf-8"))
    assert (report["command"], report["surface"]) == ("validate", "validation_report")
    assert (report["oracle"], report["candidate"], report["equal"]) == ("python", "rust", False)
    assert len(report["differences"]) == 2  # the Python issue, and the Rust one
    assert any("a different message" in line for line in report["differences"])
    assert str(tide_corpus_repo) not in written[0].read_text(encoding="utf-8")


def test_a_bad_engine_is_a_tool_error(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    monkeypatch.setenv("OPENTIDE_ENGINE", "Rust")
    with pytest.raises(ToolError, match="usage_invalid_choice"):
        tools.tool_validation_report()


def test_a_configuration_that_does_not_resolve_is_a_tool_error_on_rust(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    paths = tide_corpus_repo / ".opentide" / "configurations" / "paths.toml"
    paths.write_text("[paths\n", encoding="utf-8")
    monkeypatch.setenv("OPENTIDE_ENGINE", "rust")
    with pytest.raises(ToolError, match="command_failed"):
        tools.tool_validation_report()


# --- the SDK ---------------------------------------------------------------------------


@pytest.mark.parametrize("edit", list(EDITS))
def test_run_validation_returns_the_same_report_on_rust(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch, edit: str
) -> None:
    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation

    EDITS[edit](tide_corpus_repo)
    for scope in (
        None,
        ValidationScope.narrow(files=frozenset({_RULE})),
        ValidationScope.narrow(uuids=frozenset({_UUID}), types=frozenset({"rule"})),
    ):
        reports = {}
        for engine in ("python", "rust"):
            monkeypatch.setenv("OPENTIDE_ENGINE", engine)
            clear_runtime_caches()
            reports[engine] = _without_timing(run_validation(scope).model_dump_json_ready())
        assert reports["rust"] == reports["python"], scope


def test_run_validation_runs_python_for_what_no_command_line_does(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch, rust_calls: list[dict[str, Any]]
) -> None:
    from opentide.validation.checks.kinds import ValidateCheck
    from opentide.validation.session import run_validation

    monkeypatch.setenv("OPENTIDE_ENGINE", "rust")
    run_validation(checks=frozenset({ValidateCheck.schema, ValidateCheck.cve}))
    from opentide.core.registry import Opentide

    Opentide.initialise()
    run_validation(index=Opentide.Index)
    assert rust_calls == []
    run_validation(checks=frozenset({ValidateCheck.cve}))
    run_validation(queries_as_warnings=True)
    assert [call["queries"] for call in rust_calls] == ["error", "warn"]


def test_the_checks_a_command_line_can_run() -> None:
    default = ("a", "b", "queries")
    choose = validation_engine.default_checks_request
    assert choose(None, default, queries_as_warnings=False) == (None, "error")
    assert choose(list(default), default, queries_as_warnings=True) == (None, "warn")
    assert choose(["a", "b"], default, queries_as_warnings=False) == (None, "off")
    assert choose(["b"], default, queries_as_warnings=False) == ("b", "error")
    assert choose(["a", "queries"], default, queries_as_warnings=False) is None


def test_the_rust_report_reads_into_the_python_model() -> None:
    report = validation_engine.report_from(
        {
            "ok": False,
            "issues": [
                {
                    "code": "invalid_ref",
                    "severity": "error",
                    "file_path": "/w/x.yaml",
                    "field_path": ["a", "b"],
                    "message": "m",
                    "line": 3,
                    "explain": "opentide explain invalid_ref",
                }
            ],
            "warnings": [],
            "stats": {"objects_checked": 1, "wall_ms": 2.0},
        }
    )
    assert report.ok is False
    issue = report.issues[0]
    assert (issue.code, issue.field_path, str(issue.file_path)) == (
        "invalid_ref",
        ("a", "b"),
        "/w/x.yaml",
    )
    assert issue.to_legacy_string() == "a.b: m"
    assert validation_engine.legacy_string({"field_path": ["a", "b"], "message": "m"}) == "a.b: m"
    assert validation_engine.legacy_string({"field_path": [], "message": "m"}) == "m"
    assert report.stats == {"objects_checked": 1, "wall_ms": 2.0}


def test_differences_name_what_only_one_side_reported() -> None:
    from opentide.validation.issues import ValidationIssue, ValidationReport

    one = ValidationIssue(code="a", message="x")
    two = ValidationIssue(code="b", message="y")
    left = ValidationReport(ok=False, issues=[one, two], stats={"wall_ms": 1, "objects_checked": 2})
    same = ValidationReport(ok=False, issues=[one, two], stats={"wall_ms": 9, "objects_checked": 2})
    swapped = ValidationReport(ok=False, issues=[two, one], stats={"objects_checked": 2})
    other = ValidationReport(ok=False, issues=[one], stats={"objects_checked": 3})
    differences = validation_engine.differences
    assert differences(left, same) == []
    assert differences(left, swapped) == ["issues: the same entries in another order"]
    found = differences(left, other)
    assert len(found) == 2
    assert found[0].startswith("issues: only python:") and '"code": "b"' in found[0]
    assert found[1] == "stats.objects_checked: python 2, rust 3"
