"""MCP validation tools carry the CLI's diagnostic fields, next actions and explain pages.

Runs against tide_corpus with one rule broken on disk, so positions, fixes and
paths come from a real file rather than a patched report.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS, clear_runtime_caches

from opentide.mcp_server import tools

#: Keys an issue had before diagnostics; the tools must keep every one of them.
_ISSUE_KEYS = (
    "code",
    "severity",
    "object_uuid",
    "object_type",
    "file_path",
    "yaml_line",
    "field_path",
    "message",
    "suggestion",
    "context",
)
_DIAGNOSTIC_KEYS = ("path", "line", "column", "end_column", "help", "fix", "explain")
_RULE = Path("objects/rules/rule-0001-sentinel-kql.yaml")
_UUID = CORPUS_RULE_UUIDS["sentinel"]


@pytest.fixture
def broken_rule(tide_corpus_repo: Path) -> Path:
    """The Sentinel rule with ``tlp: clearr``, a typo with a safe fix."""
    path = tide_corpus_repo / _RULE
    text = path.read_text(encoding="utf-8")
    assert "  tlp: clear\n" in text
    path.write_text(text.replace("  tlp: clear\n", "  tlp: clearr\n", 1), encoding="utf-8")
    clear_runtime_caches()
    return path


def _tlp_issue(issues: list[dict]) -> dict:
    return next(issue for issue in issues if issue["code"] == "vocab_unknown")


def test_validation_report_issues_gain_the_diagnostic_fields(broken_rule: Path) -> None:
    payload = tools.tool_validation_report(file=str(_RULE))

    assert payload["ok"] is False
    issue = _tlp_issue(payload["issues"])
    assert set(_ISSUE_KEYS) <= issue.keys()
    assert set(_DIAGNOSTIC_KEYS) <= issue.keys()
    lines = broken_rule.read_text(encoding="utf-8").splitlines()
    # 1-based line and columns that point at the value as written.
    assert lines[issue["line"] - 1][issue["column"] - 1 : issue["end_column"] - 1] == "clearr"
    assert issue["line"] == issue["yaml_line"] + 1
    # Workspace-relative (the corpus links objects/rules to a legacy folder).
    assert not Path(issue["path"]).is_absolute()
    workspace = broken_rule.parents[2]
    assert (workspace / issue["path"]).resolve() == broken_rule.resolve()
    assert Path(issue["file_path"]).is_absolute()
    assert issue["explain"] == "opentide explain vocab_unknown"
    assert issue["help"] == "did you mean 'clear'?"
    assert issue["fix"]["safe"] is True
    assert issue["fix"]["edits"] == [
        {
            "line": issue["line"],
            "column": issue["column"],
            "end_column": issue["end_column"],
            "replacement": "clear",
        }
    ]


def test_validation_report_next_actions_explain_then_validate_again(broken_rule: Path) -> None:
    payload = tools.tool_validation_report(file=str(_RULE))

    actions = payload["next_actions"]
    assert actions[0] == {
        "tool": "explain",
        "arguments": {"code": "vocab_unknown"},
        "command": "opentide explain vocab_unknown",
        "reason": "what vocab_unknown means and how to fix it",
    }
    assert actions[-1] == {
        "tool": "validation_report",
        "arguments": {"file": str(_RULE)},
        "command": f"opentide --json validate --file {_RULE}",
        "reason": "validate again after applying the fix edits",
    }


def test_clean_validation_report_has_no_next_actions(tide_corpus_repo: Path) -> None:
    payload = tools.tool_validation_report(file=str(_RULE))

    assert payload["ok"] is True
    assert payload["next_actions"] == []
    assert payload["issues"] == []


def test_validate_rule_issues_gain_the_diagnostic_fields(broken_rule: Path) -> None:
    payload = tools.tool_validate_rule(_UUID)

    assert payload["valid"] is False
    assert set(payload) == {"valid", "errors", "warnings", "issues", "next_actions"}
    assert all(isinstance(error, str) for error in payload["errors"])
    issue = _tlp_issue(payload["issues"])
    assert set(_ISSUE_KEYS) <= issue.keys()
    assert issue["fix"]["safe"] is True
    assert payload["next_actions"][-1]["tool"] == "validate_rule"
    assert payload["next_actions"][-1]["arguments"] == {"uuid": _UUID}


def test_clean_rule_points_at_a_dry_run_deploy(tide_corpus_repo: Path) -> None:
    payload = tools.tool_validate_rule(_UUID)

    assert payload["valid"] is True
    assert payload["next_actions"] == [
        {
            "tool": "deploy_rule",
            "arguments": {"uuid": _UUID, "platform": "sentinel", "dry_run": True},
            "command": "opentide --json deploy --dry-run --platform sentinel",
            "reason": "preview the sentinel deployment; nothing is sent",
        }
    ]


def test_validate_rule_for_a_missing_rule_points_at_search(tide_corpus_repo: Path) -> None:
    missing = "00000000-0000-4000-8fff-0000000000ff"
    payload = tools.tool_validate_rule(missing)

    assert payload["valid"] is False
    assert payload["errors"] == [f"Rule {missing} not found"]
    assert payload["next_actions"][0]["tool"] == "search"


def test_explain_returns_the_cli_page() -> None:
    from opentide.cli.services.explain import load_page

    page = load_page("vocab_unknown")
    assert page is not None
    assert tools.tool_explain("vocab_unknown") == {"found": True, **page.to_dict()}


def test_explain_without_a_code_lists_every_code() -> None:
    from opentide.cli.services.explain import diagnostic_codes

    payload = tools.tool_explain("")
    assert payload["found"] is True
    assert [entry["code"] for entry in payload["codes"]] == diagnostic_codes()
    assert all(entry["meaning"] for entry in payload["codes"])


def test_explain_unknown_code_suggests_the_closest() -> None:
    payload = tools.tool_explain("vocab_unknwn")
    assert payload["found"] is False
    assert payload["suggestion"] == "vocab_unknown"
    assert "vocab_unknwn" in payload["message"]


def test_validate_query_refusal_points_at_the_live_check() -> None:
    payload = tools.tool_validate_query("SecurityEvent", "sentinel")
    assert payload["valid"] is None
    assert payload["next_actions"] == [
        {
            "tool": "validate_query",
            "arguments": {"query": "SecurityEvent", "platform": "sentinel", "live": True},
            "command": "opentide --json validate query --platform sentinel --live",
            "reason": "check the catalogue's sentinel rules against the tenant",
        }
    ]


def test_server_instructions_carry_the_tagline_and_workflow() -> None:
    from opentide.mcp_server.server import INSTRUCTIONS, mcp

    assert mcp.instructions == INSTRUCTIONS
    assert INSTRUCTIONS.startswith(
        "opentide: Spec-driven development for agentic detection engineering."
    )
    assert "ontology and a taxonomy" in INSTRUCTIONS
    for step in ("search", "validation_report", "explain(code)", "dry_run true"):
        assert step in INSTRUCTIONS
    assert "People review and merge" in INSTRUCTIONS
