"""Offline query syntax engine (#239, #245).

The default `opentide validate query` path must work from a stock install, so
every assertion here runs in-process with no vendor SDK and no tenant.
"""

from __future__ import annotations

import pytest

from opentide.validation.query_syntax import (
    PLATFORM_QUERY_LANGUAGES,
    QUERY_VALIDATION_PLATFORMS,
    check_query,
    extract_queries,
    language_label,
    query_language,
    validate_platform_queries,
)

KQL_VALID = "SecurityEvent\n| where EventID == 4688\n| take 1"


def codes(query: str, language: str) -> list[str]:
    return [finding.code for finding in check_query(query, language)]


def test_query_validation_platforms_match_the_language_table() -> None:
    assert frozenset(PLATFORM_QUERY_LANGUAGES) == QUERY_VALIDATION_PLATFORMS
    assert "crowdstrike" not in QUERY_VALIDATION_PLATFORMS
    assert "harfanglab" not in QUERY_VALIDATION_PLATFORMS


def test_query_language_is_none_for_platforms_without_one() -> None:
    assert query_language("sentinel") == "kql"
    assert query_language("crowdstrike") is None
    assert language_label("kql") == "KQL"
    assert language_label("mystery") == "MYSTERY"


@pytest.mark.parametrize(
    ("query", "language"),
    [
        (KQL_VALID, "kql"),
        ('SecurityEvent | where Account == "a|b"', "kql"),
        ("SecurityEvent // a trailing comment", "kql"),
        ("index=main | stats count by host", "spl"),
        ("search x=1 ``` a note ``` | head 1", "spl"),
        ('EventType = "Process Create"', "s1ql"),
        ("process_name:cmd.exe AND parent_name:explorer.exe", "lucene"),
        ("DeviceProcessEvents | where FileName in~ ('cmd.exe')", "kql"),
        # A generating SPL command has to start with the pipe.
        ("| tstats count from datamodel=Endpoint.Processes by _time", "spl"),
        ("| inputlookup known_hosts.csv", "spl"),
        ("| makeresults | eval marker=1", "spl"),
        # S1QL accepts a leading stage too.
        ("| group count() by endpoint.name", "s1ql"),
        # KQL verbatim literal: the backslash is data, and a Windows path that
        # ends in one must not swallow the closing quote.
        (r'DeviceProcessEvents | where FolderPath has @"C:\Windows\System32\"', "kql"),
        (r"DeviceProcessEvents | where FolderPath has @'C:\Temp\'", "kql"),
        # Lucene has no single-quoted string, so an apostrophe is just a byte.
        ("process_cmdline:*don't*", "lucene"),
        ("observer_hostname:o'brien-laptop", "lucene"),
        # S1QL spells OR as `||`; it is not an empty stage between two pipes.
        ('EventType = "Process Creation" || EventType = "Process Termination"', "s1ql"),
        ('src.process.name = "cmd.exe" || tgt.file.path = "x" | group count()', "s1ql"),
        # Lucene escapes special characters outside a phrase.
        (r"process_cmdline:*iex\(*", "lucene"),
        (r"process_cmdline:*\"http*", "lucene"),
        (r"process_name:C\:\\Windows\\System32\\cmd.exe", "lucene"),
        # Lucene ranges mix inclusive and exclusive ends.
        ("process_pid:[1000 TO 2000}", "lucene"),
        ("netconn_port:{1024 TO 65535]", "lucene"),
        # A Lucene regex is pattern, not syntax; a lone slash is just a path.
        ("process_cmdline:/.*[^)]+/", "lucene"),
        (r'process_name:/cmd\.(exe|bat)/ AND process_cmdline:/"[a-z\//', "lucene"),
        ("process_name:/usr/bin/bash", "lucene"),
        # An unescaped path is not a regex that runs on into the next term.
        ('process_name:/usr/bin/curl AND process_cmdline:"http://evil"', "lucene"),
        ('process_name:/usr/bin/bash AND process_cmdline:"/bin/sh -c"', "lucene"),
        ("process_name:/usr/bin/curl AND (process_cmdline:x OR process_name:/tmp/y)", "lucene"),
        ("(process_name:/tmp/) AND -/bad.*/^2", "lucene"),
        # KQL multi-line literal: quotes and brackets inside are data.
        (
            "let script = ```\nIEX \"(New-Object Net.WebClient)\nit's [open\n```;\n"
            "DeviceProcessEvents | where ProcessCommandLine has script",
            "kql",
        ),
        ('let s = ~~~\n"(\n~~~;\nDeviceProcessEvents | take 1', "kql"),
        ('(EventType = "a" || EventType = "b") | group count()', "s1ql"),
    ],
)
def test_well_formed_queries_produce_no_findings(query: str, language: str) -> None:
    assert codes(query, language) == []


@pytest.mark.parametrize(
    ("query", "language", "expected"),
    [
        ("", "kql", "empty_query"),
        ("   \n  ", "kql", "empty_query"),
        ('SecurityEvent | where Account == "oops', "kql", "unterminated_string"),
        ("SecurityEvent | where (EventID == 1", "kql", "unclosed_bracket"),
        ("SecurityEvent | where EventID == 1)", "kql", "unexpected_closing_bracket"),
        ("SecurityEvent | where (EventID == 1]", "kql", "bracket_mismatch"),
        ("| SecurityEvent", "kql", "leading_pipe"),
        ("SecurityEvent |", "kql", "trailing_pipe"),
        ("SecurityEvent || take 1", "spl", "empty_pipeline_stage"),
        ("SecurityEvent | where EventID == 1 and", "kql", "dangling_operator"),
        ("search x=1 ``` unfinished", "spl", "unterminated_comment"),
        # Verbatim handling must not become a blanket amnesty for KQL strings.
        (r'DeviceProcessEvents | where FolderPath has @"C:\Windows', "kql", "unterminated_string"),
        ('process_name:"cmd.exe', "lucene", "unterminated_string"),
        ("let s = ```\nnever closed", "kql", "unterminated_string"),
        ("let s = ~~~\nnever closed", "kql", "unterminated_string"),
        ('EventType = "Process Creation" ||', "s1ql", "dangling_operator"),
        # `||` is OR, so it needs an operand on each side within its stage.
        ("|| a = 'b'", "s1ql", "dangling_operator"),
        ("a = 'b' ||| columns x", "s1ql", "dangling_operator"),
        ("(|| a = 'b')", "s1ql", "dangling_operator"),
        ("(a = 'b' ||) | columns x", "s1ql", "dangling_operator"),
        ("process_pid:(1000 TO 2000]", "lucene", "bracket_mismatch"),
        ("process_pid:[1000 TO 2000", "lucene", "unclosed_bracket"),
        ("process_name:/cmd/ AND (parent_name:x", "lucene", "unclosed_bracket"),
        # A regex is only closed where its term ends, so it cannot swallow a bracket.
        ("process_name:/usr/bin (parent_name:/tmp/ OR x", "lucene", "unclosed_bracket"),
    ],
)
def test_broken_queries_report_the_expected_code(query: str, language: str, expected: str) -> None:
    assert expected in codes(query, language)


def test_findings_carry_a_usable_position() -> None:
    (finding,) = check_query('SecurityEvent\n| where Account == "oops', "kql")
    assert finding.code == "unterminated_string"
    assert finding.line == 2
    assert finding.column == 20
    assert finding.to_dict()["message"].startswith("Unterminated")


def test_masking_does_not_cascade_into_meaningless_findings() -> None:
    """An unterminated literal blanks the rest, so later checks would lie."""
    assert codes('SecurityEvent | where x == "oops (and', "kql") == ["unterminated_string"]


def test_lucene_is_not_treated_as_a_pipeline_language() -> None:
    assert codes("process_name:cmd.exe | parent:explorer.exe", "lucene") == []


def test_only_kql_rejects_a_leading_pipe() -> None:
    """A false positive here fails CI on correct content, so scope it tightly."""
    assert codes("| where EventID == 1", "kql") == ["leading_pipe"]
    for language in ("spl", "s1ql"):
        assert codes("| stats count by host", language) == [], language


def test_a_trailing_pipe_is_still_wrong_in_every_pipeline_language() -> None:
    """Relaxing the leading pipe must not relax the rest of the stage check."""
    for language in ("kql", "spl", "s1ql"):
        assert "trailing_pipe" in codes("index=main | stats count |", language), language


def test_only_kql_reads_an_at_prefixed_literal_as_verbatim() -> None:
    """``@`` is not a string prefix elsewhere, so the backslash still escapes."""
    assert codes(r'search path="C:\Temp\"', "spl") == ["unterminated_string"]
    assert codes(r'DeviceProcessEvents | where FolderPath has @"C:\Temp\"', "kql") == []


def test_a_doubled_quote_escapes_inside_a_verbatim_literal() -> None:
    assert codes(r'DeviceProcessEvents | where Cmd has @"say ""hi"" now"', "kql") == []


def test_only_lucene_ignores_the_apostrophe() -> None:
    assert codes("field:o'brien", "lucene") == []
    assert codes("SecurityEvent | where Account has 'o", "kql") == ["unterminated_string"]


def test_each_relaxation_stays_in_its_own_language() -> None:
    """A false negative elsewhere is the price of a blanket rule, so scope them."""
    # `||` is only OR in S1QL; KQL and SPL have no such operator.
    for language in ("kql", "spl"):
        assert "empty_pipeline_stage" in codes("T | where a == 1 || b == 2", language), language
    # Only Lucene ranges may mix bracket kinds.
    assert codes("T | where x in [1, 2}", "kql") == ["bracket_mismatch"]
    # Only KQL reads triple backticks as a string; in SPL they are a comment.
    assert codes("search x=1 ``` it's a note ``` | head 1", "spl") == []
    assert codes('```\nsay "hi\n```', "s1ql") == ["unterminated_string"]
    assert codes('~~~\nsay "hi\n~~~', "s1ql") == ["unterminated_string"]
    # Only Lucene escapes outside a phrase.
    assert codes(r"SecurityEvent | where Cmd has \(", "kql") == ["unclosed_bracket"]
    # Only Lucene reads /.../ as a regex.
    assert codes("index=main | where x=/(/", "spl") == ["unclosed_bracket"]


def test_a_trailing_lucene_escape_does_not_crash_the_scan() -> None:
    assert codes("process_name:cmd\\", "lucene") == []


def test_an_escaped_quote_does_not_end_a_string() -> None:
    assert codes(r'SecurityEvent | where Account == "say \"hi\""', "kql") == []
    assert codes(r'SecurityEvent | where Account == "say \"hi', "kql") == ["unterminated_string"]


def test_line_comments_are_masked_wherever_they_sit() -> None:
    assert codes("SecurityEvent | take 1 // done", "kql") == []
    assert codes('SecurityEvent // a "quote" and (bracket\n| take 1', "kql") == []


def test_a_blank_query_body_after_masking_is_not_a_dangling_operator() -> None:
    assert codes("// only a comment", "kql") == []


def test_extract_queries_reads_the_flat_query_field() -> None:
    body = {
        "name": "Flat rule",
        "configurations": {"sentinel": {"query": KQL_VALID}},
    }
    (spec,) = extract_queries("sentinel", "uuid-1", body)
    assert spec.field == "configurations.sentinel.query"
    assert spec.language == "kql"
    assert spec.rule == "Flat rule"


def test_extract_queries_reads_the_splunk_legacy_search_field() -> None:
    body = {"configurations": {"splunk": {"search": "index=main | head 1"}}}
    (spec,) = extract_queries("splunk", "uuid-2", body)
    assert spec.field == "configurations.splunk.search"


def test_extract_queries_walks_sentinel_one_conditions() -> None:
    body = {
        "configurations": {
            "sentinel_one": {
                "condition": {
                    "single_event": {"query": 'EventType = "Process Create"'},
                    "correlation": {
                        "sub_queries": [
                            {"query": 'SrcProcName = "cmd.exe"'},
                            {"matches_required": 1},
                        ]
                    },
                }
            }
        }
    }
    fields = [spec.field for spec in extract_queries("sentinel_one", "uuid-3", body)]
    assert fields == [
        "configurations.sentinel_one.condition.single_event.query",
        "configurations.sentinel_one.condition.correlation.sub_queries[0].query",
    ]


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"condition": "not-a-mapping"},
        {"condition": {"single_event": "not-a-mapping"}},
        {"condition": {"single_event": {"query": 42}}},
        {"condition": {"correlation": {"sub_queries": "not-a-list"}}},
    ],
)
def test_sentinel_one_extraction_tolerates_a_malformed_condition(config: dict) -> None:
    body = {"configurations": {"sentinel_one": config}}
    assert extract_queries("sentinel_one", "uuid-6", body) == []


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"configurations": "not-a-mapping"},
        {"configurations": {"splunk": {"query": "index=main"}}},
        {"configurations": {"sentinel": {"enabled": True}}},
    ],
)
def test_extract_queries_returns_nothing_when_there_is_no_query(body: dict) -> None:
    assert extract_queries("sentinel", "uuid-4", body) == []


def test_extract_queries_skips_platforms_without_a_language() -> None:
    body = {"configurations": {"crowdstrike": {"query": "anything"}}}
    assert extract_queries("crowdstrike", "uuid-5", body) == []


def test_validate_platform_queries_aggregates_and_locates_findings() -> None:
    rules = {
        "uuid-ok": {"name": "Good", "configurations": {"sentinel": {"query": KQL_VALID}}},
        "uuid-bad": {
            "name": "Bad",
            "configurations": {"sentinel": {"query": 'SecurityEvent | where x == "oops'}},
        },
        "uuid-other": {"configurations": {"splunk": {"query": "index=main"}}},
    }
    report = validate_platform_queries("sentinel", rules)
    assert (report.rules, report.checked, report.ok) == (2, 2, False)
    (finding,) = report.findings
    assert finding["uuid"] == "uuid-bad"
    assert finding["rule"] == "Bad"
    assert finding["code"] == "unterminated_string"
    assert report.to_dict()["language"] == "kql"


def test_validate_platform_queries_honours_a_uuid_scope() -> None:
    rules = {
        "uuid-ok": {"configurations": {"sentinel": {"query": KQL_VALID}}},
        "uuid-bad": {"configurations": {"sentinel": {"query": "SecurityEvent |"}}},
    }
    report = validate_platform_queries("sentinel", rules, uuids=frozenset({"uuid-ok"}))
    assert (report.checked, report.ok) == (1, True)


def test_validate_platform_queries_rejects_a_platform_without_a_language() -> None:
    with pytest.raises(ValueError, match="crowdstrike"):
        validate_platform_queries("crowdstrike", {})
