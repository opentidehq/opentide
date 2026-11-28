//! A finding at the end of an injected query is placed where the query
//! stops, not at its start (#1431). An engine reports "missing `)`" or
//! "expected an expression" as an empty span at the query's length, which
//! `host_map` has no entry for: `remap_span` put it on the query's first
//! byte, so `validate`'s frame took the whole query and the editor's squiggle
//! sat on its first character.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::{ByteSpan, LanguageId, Position};
use opentide_tide::{analyze_queries, extract_injections, remap_span};

/// Each query as a block scalar that ends the document, as a rule file's
/// last key does.
const CQL: &str = "configurations:\n  crowdstrike:\n    query: |\n      a=1 | groupBy(\n";
const YARA: &str =
    "configurations:\n  bitdefender:\n    yara:\n      signature: |\n        rule a { condition:\n";
const ESQL: &str =
    "configurations:\n  elastic:\n    type: esql\n    query: |\n      FROM logs-* | WHERE (\n";
const EXABEAM: &str =
    "configurations:\n  exabeam:\n    sequences:\n      - query: |\n          a =\n";

/// The start of the first parse error of `language` in `source`.
fn parse_error_start(source: &str, language: LanguageId) -> Position {
    let analysis = analyze_queries(source, &[]);
    let query = analysis
        .iter()
        .find(|q| q.query.language == language)
        .unwrap_or_else(|| panic!("no {language:?} query in\n{source}"));
    let error = query
        .diagnostics
        .iter()
        .find(|d| d.code.ends_with("_parse_error"))
        .unwrap_or_else(|| panic!("no parse error: {:?}", query.diagnostics));
    error.range.start
}

/// Right after the query's last character, on its last line: where the
/// text stops (the block scalar's final newline is not part of the query).
fn after_the_query(source: &str) -> Position {
    let lines: Vec<&str> = source.lines().collect();
    let last = lines.len() - 1;
    Position::new(
        u32::try_from(last).unwrap(),
        u32::try_from(lines[last].len()).unwrap(),
    )
}

#[test]
fn a_span_at_the_query_end_is_right_after_its_last_byte() {
    let query = &extract_injections(CQL)[0];
    let len = query.inner.len();
    let after_last = query.host_map[len - 1] + 1;
    // The block's final newline, right after `(`.
    assert_eq!(after_last, CQL.len() - 1);
    // Empty at the end, one past it, and a span that runs to the end.
    assert_eq!(
        remap_span(query, ByteSpan::new(len, len)),
        ByteSpan::new(after_last, after_last)
    );
    assert_eq!(
        remap_span(query, ByteSpan::new(len, len + 1)),
        ByteSpan::new(after_last, after_last)
    );
    assert_eq!(
        remap_span(query, ByteSpan::new(len - 1, len)),
        ByteSpan::new(after_last - 1, after_last)
    );
    // Inside the query nothing moves.
    assert_eq!(
        remap_span(query, ByteSpan::new(0, 3)),
        ByteSpan::new(query.host_map[0], query.host_map[2] + 1)
    );
}

#[test]
fn a_cql_query_that_stops_early_is_reported_where_it_stops() {
    assert_eq!(
        parse_error_start(CQL, LanguageId::Cql),
        after_the_query(CQL)
    );
}

#[test]
fn a_yara_rule_that_stops_early_is_reported_where_it_stops() {
    assert_eq!(
        parse_error_start(YARA, LanguageId::Yara),
        after_the_query(YARA)
    );
}

#[test]
fn an_exabeam_filter_that_stops_early_is_reported_where_it_stops() {
    assert_eq!(
        parse_error_start(EXABEAM, LanguageId::Exabeam),
        after_the_query(EXABEAM)
    );
}

/// A double-quoted query: the end is its closing quote, where the text stops.
#[test]
fn a_quoted_query_that_stops_early_is_reported_at_its_closing_quote() {
    let source = "configurations:\n  crowdstrike:\n    query: \"a=1 | groupBy(\"\n";
    let quote = source.rfind('"').unwrap();
    let line_start = source[..quote].rfind('\n').unwrap() + 1;
    assert_eq!(
        parse_error_start(source, LanguageId::Cql),
        Position::new(2, u32::try_from(quote - line_start).unwrap())
    );
}

/// ES|QL reports an error at the end as the other engines do, an empty span
/// where the text stops, and lands right after the query's last character
/// (it used to mark that character itself, a workaround #1431 made needless).
#[test]
fn an_esql_query_that_stops_early_is_reported_where_it_stops() {
    assert_eq!(
        parse_error_start(ESQL, LanguageId::Esql),
        after_the_query(ESQL)
    );
}
