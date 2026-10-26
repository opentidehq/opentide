//! Query strings from Apache Lucene's own parser tests (`TestQueryParser`,
//! `QueryParserTestBase`, Apache-2.0), with the verdict the Lucene 10.5.2
//! classic parser gives each one (leading wildcards allowed, as
//! Elasticsearch allows them). Source, pin, and licence:
//! `testdata/conformance/external/SOURCES.md`.
//!
//! An accepted query must produce no engine error, and a rejected one must
//! produce one, except for the cases listed below with the reason.

use opentide_core::Severity;
use std::path::PathBuf;

/// Lucene's verdict differs from Elasticsearch's here, or the engine reports
/// something Lucene's parser does not check.
const EXCEPTIONS: &[(&str, &str)] = &[
    // Elasticsearch reads `~N` as a fuzziness (0, 1, 2, or AUTO); Lucene
    // clamps a larger distance and reads a fraction below 1 as similarity.
    (
        "term~0.7",
        "Elasticsearch accepts only whole fuzziness values (0, 1, 2) or AUTO; Lucene reads 0.7 as a similarity",
    ),
];

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn lucene_parser_test_queries() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance/external/lucene-queryparser/cases.tsv");
    let text = std::fs::read_to_string(path).expect("cases.tsv");
    let mut checked = 0;
    let mut wrong = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let mut cols = line.split('\t');
        let (Some(verdict), Some(query), Some(source)) = (cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        let query = unescape(query);
        let diagnostics = opentide_lucene::analyze(&query).diagnostics;
        let errors: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.code.as_str())
            .collect();
        let agrees = match verdict {
            "accept" => errors.is_empty(),
            "reject" => !errors.is_empty(),
            other => panic!("unknown verdict {other}"),
        };
        checked += 1;
        if !agrees && !EXCEPTIONS.iter().any(|(q, _)| *q == query) {
            wrong.push(format!("{verdict} {query:?} ({source}): {errors:?}"));
        }
    }
    assert!(
        checked > 300,
        "expected the Lucene test corpus, found {checked}"
    );
    assert!(
        wrong.is_empty(),
        "{} disagreements:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
