//! The engine against the reference checker of specifications exabeam-1.0
//! (`scripts/exabeam_language.py`), whose verdicts on every conformance query
//! `scripts/sync_exabeam_conformance.py` records in
//! `testdata/conformance/exabeam/reference.json`: the spec's fixtures, the
//! queries of `testdata/conformance/external/exabeam/` and the probes of
//! `probes.tsv`.
//!
//! Codes, ranges and highlight tokens must be the reference's, but for the
//! differences `DIFFERENCES` lists with their reason (`docs/EXABEAM.md`).

use opentide_exabeam::{Profile, check};
use std::path::PathBuf;

/// Catalogue warnings: the reference checker has no catalogue.
const CATALOGUE_CODES: [&str; 2] = ["exabeam_unknown_field", "exabeam_string_field_number"];

/// Codes whose range the engine narrows: the reference checker reports them
/// from the start of the query to the end of the statement; the engine on the
/// column (`exabeam_group_by_column`) or the `*` (`exabeam_group_by_select_star`).
const NARROWED: [&str; 2] = ["exabeam_group_by_column", "exabeam_group_by_select_star"];

/// Queries where the engine follows RE2 and the reference checker, which
/// approximates RE2 with Python's `re`, does not.
const DIFFERENCES: &[(&str, &str)] = &[
    // RE2 escapes only ASCII punctuation: `\` before U+00A0 is an invalid
    // escape. Python takes it as the character.
    ("probes.tsv:158", "exabeam_regex"),
    // RE2 repeats an empty-width assertion (`$?`); Python refuses it
    // ("nothing to repeat").
    ("probes.tsv:159", "-exabeam_regex"),
];

#[test]
fn the_engine_agrees_with_the_reference_checker() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance/exabeam/reference.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let queries = doc["queries"].as_array().unwrap();
    assert!(queries.len() >= 200, "{}", queries.len());
    let mut failures = Vec::new();
    let mut differences_seen = Vec::new();
    for q in queries {
        let name = q["name"].as_str().unwrap();
        let text = q["text"].as_str().unwrap();
        let profile = Profile::parse(q["profile"].as_str().unwrap()).unwrap();
        let checked = check(text, profile);
        let mut expected: Vec<(String, usize, usize)> = q["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d[0].as_str().unwrap().to_string(),
                    d[1].as_u64().unwrap() as usize,
                    d[2].as_u64().unwrap() as usize,
                )
            })
            .collect();
        let mut found: Vec<(String, usize, usize)> = checked
            .findings
            .iter()
            .filter(|f| !CATALOGUE_CODES.contains(&f.code))
            .map(|f| (f.code.to_string(), f.start, f.end))
            .collect();
        for list in [&mut expected, &mut found] {
            for d in list.iter_mut() {
                if NARROWED.contains(&d.0.as_str()) {
                    d.1 = 0;
                    d.2 = 0;
                }
            }
            list.sort();
        }
        if let Some((_, difference)) = DIFFERENCES.iter().find(|(n, _)| *n == name) {
            differences_seen.push(name);
            let (code, engine_only) = match difference.strip_prefix('-') {
                Some(code) => (code, false),
                None => (*difference, true),
            };
            let (with, without) = if engine_only {
                (&found, &expected)
            } else {
                (&expected, &found)
            };
            assert!(
                with.iter().any(|d| d.0 == code) && !without.iter().any(|d| d.0 == code),
                "{name}: the listed difference is gone; engine {found:?}, reference {expected:?}"
            );
            continue;
        }
        if found != expected {
            failures.push(format!(
                "{name} ({text:?}): engine {found:?}, reference {expected:?}"
            ));
            continue;
        }
        let tokens: Vec<(usize, usize, String)> = q["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t[0].as_u64().unwrap() as usize,
                    t[1].as_u64().unwrap() as usize,
                    t[2].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let engine_tokens: Vec<(usize, usize, String)> = checked
            .tokens
            .iter()
            .map(|t| (t.start, t.end, t.capture.to_string()))
            .collect();
        if engine_tokens != tokens {
            failures.push(format!(
                "{name} ({text:?}): tokens {engine_tokens:?}, reference {tokens:?}"
            ));
        }
    }
    assert_eq!(
        differences_seen.len(),
        DIFFERENCES.len(),
        "{differences_seen:?}"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Queries whose highlighting differs, with the reason.
const HIGHLIGHT_DIFFERENCES: &[&str] = &[
    // A second `SELECT` after a filter: the reference checker reads it as free
    // text (and warns `exabeam_implicit_and`); the grammar, which parses
    // clauses in any order, as a clause keyword.
    "probes.tsv:64",
];

/// The tree-sitter grammar's highlighting matches the reference checker's
/// tokens on every query the reference finds no error in.
#[test]
fn tree_sitter_highlighting_agrees_on_error_free_queries() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance/exabeam/reference.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let spec = opentide_highlight::HighlightSpec::load().unwrap();
    let mut failures = Vec::new();
    let mut compared = 0;
    for q in doc["queries"].as_array().unwrap() {
        let errors = q["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| !opentide_exabeam::is_warning(d[0].as_str().unwrap()));
        let name = q["name"].as_str().unwrap();
        if errors || HIGHLIGHT_DIFFERENCES.contains(&name) {
            continue;
        }
        compared += 1;
        let text = q["text"].as_str().unwrap();
        let expected: Vec<(usize, usize, String)> = q["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t[0].as_u64().unwrap() as usize,
                    t[1].as_u64().unwrap() as usize,
                    t[2].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let got: Vec<(usize, usize, String)> = opentide_exabeam::highlight(&spec, text)
            .into_iter()
            .map(|t| (t.span.start, t.span.end, t.capture))
            .collect();
        if got != expected {
            failures.push(format!(
                "{} ({text:?}):\n  tree-sitter {got:?}\n  reference   {expected:?}",
                q["name"]
            ));
        }
    }
    assert!(compared >= 100, "{compared}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
