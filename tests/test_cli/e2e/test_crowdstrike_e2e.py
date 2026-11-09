"""CLI E2E: CrowdStrike Next-Gen SIEM queries checked offline as CQL (crowdstrike-1.0)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

RULE = "rule-0006-crowdstrike-deploy-only.yaml"
#: The corpus rule's query, a bare field filter, which is valid CQL.
QUERY_LINE = "    query: index=main\n"


def _rule_path(repo: Path) -> Path:
    (path,) = repo.rglob(RULE)
    return path


def _break_the_query(repo: Path) -> Path:
    """Give the corpus rule a query with a misspelt function: `groupBy` as `groupBi`."""
    path = _rule_path(repo)
    text = path.read_text(encoding="utf-8")
    assert QUERY_LINE in text
    path.write_text(
        text.replace(
            QUERY_LINE,
            "    query: |\n"
            "      #event_simpleName=ProcessRollup2 event_platform=Win\n"
            "      | groupBi([aid, ComputerName], function=count())\n",
        ),
        encoding="utf-8",
    )
    return path


def test_the_corpus_crowdstrike_rule_validates(invoke_cli, tide_corpus_repo: Path) -> None:
    assert_json_ok(invoke_cli("validate", "--file", RULE))


def test_validate_query_checks_the_rule_as_cql_offline(invoke_cli, tide_corpus_repo: Path) -> None:
    payload = assert_json_ok(
        invoke_cli("validate", "query", "--platform", "crowdstrike", "--file", RULE)
    )
    assert payload["mode"] == "offline"
    assert [(item["platform"], item["language"]) for item in payload["queries"]] == [
        ("crowdstrike", "cql")
    ]


def test_validate_fails_a_rule_with_an_unknown_function(invoke_cli, tide_corpus_repo: Path) -> None:
    path = _break_the_query(tide_corpus_repo)
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1, result.output
    assert "cql_unknown_function" in result.output
    (issue,) = parse_cli_json(result)["report"]["issues"]
    assert issue["code"] == "cql_unknown_function"
    assert issue["severity"] == "error"
    assert issue["field_path"] == ["configurations", "crowdstrike", "query"]
    assert issue["suggestion"] == "groupBy"
    # The position is in the rule file, on the misspelt name.
    line = path.read_text(encoding="utf-8").splitlines()[issue["line"] - 1]
    assert line[issue["column"] - 1 : issue["end_column"] - 1] == "groupBi"


def test_lint_reports_a_cql_warning(invoke_cli, tide_corpus_repo: Path) -> None:
    """A misspelt event name is a warning: lint reports it, validate passes."""
    path = _rule_path(tide_corpus_repo)
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace(QUERY_LINE, "    query: '#event_simpleName=ProcesRollup2'\n"),
        encoding="utf-8",
    )
    assert_json_ok(invoke_cli("validate", "--file", RULE))
    result = invoke_cli("lint", "--check", "queries")
    assert "cql_unknown_event" in result.output, result.output


def test_validate_query_checks_a_cql_file_offline(invoke_cli, tmp_path: Path) -> None:
    clean = tmp_path / "whoami.cql"
    clean.write_text(
        "#event_simpleName=ProcessRollup2 | groupBy([aid, ComputerName])\n", encoding="utf-8"
    )
    assert_json_ok(
        invoke_cli("validate", "query", "--platform", "crowdstrike", "--file", str(clean))
    )
    broken = tmp_path / "broken.cql"
    broken.write_text("#event_simpleName=ProcessRollup2 | groupBy([aid\n", encoding="utf-8")
    result = invoke_cli("validate", "query", "--platform", "crowdstrike", "--file", str(broken))
    assert result.exit_code == 1
    assert "cql_parse_error" in result.output


def test_validate_query_live_reports_crowdstrike_unsupported(invoke_cli) -> None:
    """No tenant check: --live never fakes one."""
    result = invoke_cli("validate", "query", "--platform", "crowdstrike", "--live")
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert payload["supported"] is False
    assert payload["valid"] is None
    assert payload["platform"] == "crowdstrike"
