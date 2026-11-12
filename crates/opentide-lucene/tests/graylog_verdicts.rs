//! The Graylog dialect against recorded live-Graylog verdicts.
//!
//! `testdata/oracles/graylog/*.lucene` are probes sent to
//! `POST /api/search/validate` on Graylog 7.2.2 and 6.3.5
//! (`scripts/oracles/graylog/probes.py`); `expected.tsv` records the status
//! per release line. Graylog's validator parses the query with Lucene's
//! classic parser and compiles each regex; ERROR means deploy saves nothing.
//! This test needs no server. It holds the engine to those verdicts:
//!
//! - ERR on every release: the engine reports an Error;
//! - OK or WARN: the engine reports no Error, except the silent failures the
//!   Graylog dialect reports on purpose (`SILENT`) and `EXCEPTIONS`.
//!
//! `CODES` names the finding each probe that targets a dialect code must get.

use opentide_core::{Severity, codes};
use opentide_lucene::{Dialect, analyze_dialect};
use std::fs;
use std::path::PathBuf;

/// Accepted by Graylog's validator, yet no message ever matches: the engine
/// reports an error on purpose (graylog-1.0, "Query diagnostics").
const SILENT: &[(&str, &str)] = &[
    ("regex_inline_flag.lucene", codes::GRAYLOG_REGEX_UNSUPPORTED),
    ("regex_lookahead.lucene", codes::GRAYLOG_REGEX_UNSUPPORTED),
    (
        "regex_non_capturing.lucene",
        codes::GRAYLOG_REGEX_UNSUPPORTED,
    ),
    (
        "regex_backreference.lucene",
        codes::GRAYLOG_REGEX_UNSUPPORTED,
    ),
];

/// Where the engine and Graylog's validator disagree, with the reason. A
/// listed probe the engine now agrees with fails, so the list stays exact.
const EXCEPTIONS: &[(&str, &str)] = &[
    // The validator parses with Lucene, which ignores a fuzziness it cannot
    // read; OpenSearch's `query_string` rejects it at search time.
    ("fuzzy_word.lucene", SEARCH_TIME),
];

const SEARCH_TIME: &str = "OpenSearch refuses it when the search runs";

/// The finding each dialect probe must get.
const CODES: &[(&str, &str)] = &[
    ("leading_star.lucene", codes::GRAYLOG_LEADING_WILDCARD),
    (
        "leading_question_mark.lucene",
        codes::GRAYLOG_LEADING_WILDCARD,
    ),
    ("star_alone.lucene", codes::GRAYLOG_LEADING_WILDCARD),
    ("field_star.lucene", codes::GRAYLOG_LEADING_WILDCARD),
    (
        "leading_star_in_group.lucene",
        codes::GRAYLOG_LEADING_WILDCARD,
    ),
    ("prohibited_star.lucene", codes::GRAYLOG_LEADING_WILDCARD),
    ("leading_star_fuzzy.lucene", codes::GRAYLOG_LEADING_WILDCARD),
    (
        "regex_word_boundary.lucene",
        codes::GRAYLOG_REGEX_UNSUPPORTED,
    ),
    (
        "regex_not_word_boundary.lucene",
        codes::GRAYLOG_REGEX_UNSUPPORTED,
    ),
    ("regex_tilde.lucene", codes::GRAYLOG_REGEX_OPERATOR),
    ("regex_hash.lucene", codes::GRAYLOG_REGEX_OPERATOR),
    ("regex_ampersand.lucene", codes::GRAYLOG_REGEX_OPERATOR),
    ("regex_greater_than.lucene", codes::GRAYLOG_REGEX_OPERATOR),
    ("regex_quoted_literal.lucene", codes::GRAYLOG_REGEX_QUOTE),
    // Graylog's validator fails on an open bound (a null term in its
    // TermRangeQuery handling) though OpenSearch runs it. It also refuses
    // `*:*`, which the engine reports as a leading wildcard.
    ("range_open_upper.lucene", codes::GRAYLOG_OPEN_RANGE),
    ("range_open_lower.lucene", codes::GRAYLOG_OPEN_RANGE),
    ("four_backslashes.lucene", codes::GRAYLOG_DOUBLE_BACKSLASH),
    ("analyzed_regex.lucene", codes::GRAYLOG_ANALYZED_FIELD),
    ("analyzed_wildcard.lucene", codes::GRAYLOG_ANALYZED_FIELD),
    ("analyzed_range.lucene", codes::GRAYLOG_ANALYZED_FIELD),
    ("lowercase_and.lucene", codes::LUCENE_LOWERCASE_OPERATOR),
    ("bare_term.lucene", codes::LUCENE_BARE_TERM),
    ("regex_unclosed_interval.lucene", codes::LUCENE_REGEXP),
    ("regex_unpaired_quote.lucene", codes::LUCENE_REGEXP),
    ("unclosed_group.lucene", codes::LUCENE_PARSE_ERROR),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/oracles/graylog")
}

#[test]
fn the_graylog_dialect_agrees_with_live_graylog() {
    let table = fs::read_to_string(root().join("expected.tsv")).unwrap();
    let mut rows = table.lines();
    let header: Vec<&str> = rows.next().unwrap().split('\t').collect();
    assert_eq!(header[0], "probe");
    let mut checked = 0;
    let mut wrong = Vec::new();
    let mut stale = Vec::new();
    for row in rows {
        let cells: Vec<&str> = row.split('\t').collect();
        let (name, verdicts) = (cells[0], &cells[1..]);
        assert_eq!(verdicts.len(), header.len() - 1, "{row}");
        let rejected = verdicts.iter().all(|v| *v == "ERR");
        assert!(
            rejected || verdicts.iter().all(|v| *v != "ERR"),
            "{name}: the releases disagree; record the version gap first"
        );
        let text = fs::read_to_string(root().join(name)).unwrap();
        let found = analyze_dialect(&text, Dialect::Graylog).diagnostics;
        let error = found.iter().any(|d| d.severity == Severity::Error);
        let silent = SILENT.iter().find(|(n, _)| *n == name);
        let agrees = error == (rejected || silent.is_some());
        match (agrees, EXCEPTIONS.iter().any(|(n, _)| *n == name)) {
            (false, false) => wrong.push(format!("{name}: Graylog {verdicts:?}, engine {found:?}")),
            (true, true) => stale.push(name),
            _ => {}
        }
        for (_, code) in CODES.iter().chain(SILENT).filter(|(n, _)| *n == name) {
            assert!(
                found.iter().any(|d| d.code == *code),
                "{name}: expected {code}, found {found:?}"
            );
        }
        checked += 1;
    }
    assert!(wrong.is_empty(), "disagreements:\n{}", wrong.join("\n"));
    assert!(stale.is_empty(), "stale exceptions: {stale:?}");
    let probes = fs::read_dir(root())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "lucene")
        })
        .count();
    assert_eq!(checked, probes, "every probe has a verdict");
    assert!(checked >= 50, "{checked} probes");
}
