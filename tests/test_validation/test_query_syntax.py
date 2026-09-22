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
