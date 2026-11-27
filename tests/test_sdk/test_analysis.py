"""``opentide.analysis``: one query checked offline, and the engine's highlighting.

Each function calls the engine compiled into the package (``opentide._native``)
in process; positions are the command line's (1-based lines, columns in code
points, ``end_column`` exclusive).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide import Workspace, analysis
from opentide._native import analyze_query


def test_a_query_with_an_error_reports_it_where_it_is() -> None:
    [finding] = analysis.check_query("SecurityEvent | wher x", language="kql")
    assert finding == analysis.Finding(
        code="kql_unknown_operator",
        severity="error",
        message="unknown tabular operator 'wher'",
        line=1,
        column=17,
        end_line=1,
        end_column=23,
        suggestion="where",
    )
    assert finding.single_line_end == 23


def test_a_clean_query_has_no_finding() -> None:
    assert analysis.check_query("SecurityEvent | take 1", language="kql") == []


def test_columns_count_code_points_not_utf16_units() -> None:
    text = 'SecurityEvent | where Account == "😀" | wher x'
    [finding] = analysis.check_query(text, language="kql")
    assert finding.code == "kql_unknown_operator"
    assert finding.column == text.index("wher x") + 1


def test_the_platform_selects_the_schema() -> None:
    query = "Nope | take 1"
    [finding] = analysis.check_query(query, language="kql", platform="microsoft_defender")
    assert (finding.code, finding.severity) == ("kql_unknown_table", "error")
    assert (
        analysis.check_query(
            "DeviceProcessEvents | take 1", language="kql", platform="microsoft_defender"
        )
        == []
    )


def test_the_stack_reaches_esql() -> None:
    codes = {
        finding.code
        for finding in analysis.check_query("FROM logs-* | LIMIT 1", language="esql", stack="9.1")
    }
    assert "esql_metadata_id" in codes


CORRELATE_THEN_AGGREGATE = (
    "correlate(A: { #event_simpleName=UserLogon }, B: { #event_simpleName=ProcessRollup2"
    " | aid <=> A.aid }, within=10m) | groupBy(aid)"
)
EXABEAM_SEARCH = 'SELECT DISTINCT user, src_ip WHERE vendor:"Microsoft"'


@pytest.mark.parametrize(
    ("query", "language", "platform", "code"),
    [
        (CORRELATE_THEN_AGGREGATE, "cql", "crowdstrike", "cql_correlate_aggregate"),
        (EXABEAM_SEARCH, "exabeam", "exabeam", "exabeam_advanced_in_rule"),
    ],
)
def test_the_rule_position_checks_the_query_as_its_rule_block(
    query: str, language: str, platform: str, code: str
) -> None:
    """``position="rule"`` restores the rule-only checks; a search has none (#1993)."""
    search = analysis.check_query(query, language=language, platform=platform)
    assert code not in {finding.code for finding in search}
    rule = analysis.check_query(query, language=language, platform=platform, position="rule")
    assert code in {finding.code for finding in rule}


def test_a_rule_position_needs_a_platform() -> None:
    with pytest.raises(ValueError, match="needs a platform"):
        analysis.check_query(CORRELATE_THEN_AGGREGATE, language="cql", position="rule")


def test_an_unknown_position_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown position"):
        analyze_query("x", "cql", platform="crowdstrike", position="hunt")  # ty: ignore[invalid-argument-type]  # the refusal under test


def test_an_unknown_spl_command_points_at_lint_toml_not_a_declaration() -> None:
    [finding] = analysis.check_query("index=main | nosuchcmd", language="spl")
    assert finding.code == "spl_unknown_command"
    assert "[queries.codes]" in finding.message
    assert "declare" not in finding.message


def test_a_span_that_ends_on_a_newline_ends_on_its_own_line() -> None:
    [finding] = analysis.check_query("SecurityEvent | where (\n", language="kql")
    assert finding.code == "kql_parse_error"
    assert finding.end_line == finding.line


def test_a_workspace_run_leaves_the_declared_datasets_as_it_found_them(
    tide_corpus_repo: Path,
) -> None:
    # validate and lint install the workspace's visibility.toml for their run
    # only: a query checked on its own afterwards is checked as before.
    (tide_corpus_repo / ".opentide/configurations/visibility.toml").write_text(
        '[[logsources]]\nname = "SecurityEvent"\ndescription = "x"\nsystem = "sentinel"\n',
        encoding="utf-8",
    )
    query = "DeviceProcessEvents | take 1"
    before = analyze_query(query, "kql")
    assert "kql_table_not_declared" not in {diagnostic.code for diagnostic in before}
    ws = Workspace.open(tide_corpus_repo)
    ws.validate()
    assert [diagnostic.code for diagnostic in analyze_query(query, "kql")] == [
        diagnostic.code for diagnostic in before
    ]
    ws.lint()
    assert [diagnostic.code for diagnostic in analyze_query(query, "kql")] == [
        diagnostic.code for diagnostic in before
    ]


def test_an_unknown_language_is_a_value_error() -> None:
    with pytest.raises(ValueError, match='unknown language "cobol": expected one of kql'):
        analysis.check_query("x", language="cobol")
    with pytest.raises(ValueError, match="unknown language"):
        analysis.highlight("x", "cobol")


def test_an_object_file_is_not_a_query() -> None:
    with pytest.raises(ValueError, match="opentide-yaml is an object file, not a query"):
        analysis.check_query("name: x\n", language="opentide-yaml")


def test_the_engines_diagnostic_names_its_place_and_code() -> None:
    [diagnostic] = analyze_query("SecurityEvent | wher x", "kql")
    assert repr(diagnostic) == (
        "Diagnostic(1:17:23 error[kql_unknown_operator] \"unknown tabular operator 'wher'\")"
    )
    assert diagnostic.field_path is None


def test_highlighting_colours_a_query() -> None:
    tokens = analysis.highlight("SecurityEvent | take 1", "kql")
    assert tokens[:3] == [
        analysis.HighlightToken(1, 1, 1, 14, "type"),
        analysis.HighlightToken(1, 15, 1, 16, "operator.pipe"),
        analysis.HighlightToken(1, 17, 1, 21, "keyword"),
    ]


def test_highlighting_colours_the_query_inside_an_object() -> None:
    query = "SecurityEvent | take 1"
    prefix = "    query: "
    text = f"name: Example\nconfigurations:\n  sentinel:\n{prefix}{query}\n"
    tokens = analysis.highlight(text, "opentide-yaml")
    # The query's own tokens, on line 4, shifted by the key before it.
    shift = len(prefix)
    assert [token for token in tokens if token.line == 4][-4:] == [
        analysis.HighlightToken(4, token.column + shift, 4, token.end_column + shift, token.capture)
        for token in analysis.highlight(query, "kql")
    ]


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("objects/rules/a.YML", "opentide-yaml"),
        ("hunt.esql", "esql"),
        ("notes.txt", None),
        ("Makefile", None),
    ],
)
def test_a_file_name_implies_its_language(path: str, language: str | None) -> None:
    assert analysis.language_for_path(path) == language


def test_the_engine_describes_its_codes() -> None:
    codes = analysis.engine_codes()
    assert "kql_unknown_table" in codes
    assert len(codes) == len(set(codes))
    description = analysis.describe("kql_unknown_table")
    assert description is not None
    assert "visibility.toml" in description
    assert analysis.describe("not_a_code") is None
    assert analysis.engine_versions()["engine"]
