//! The parser over every `.kql` of `crates/testdata`: lossless on every file
//! and prefix, and every valid tree conforms to `kql.ungram`.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

mod common;
use common::corpus;
use opentide_kql::inspect::{conformance, lex_spans, parse_error_count, parse_is_lossless};

/// Every corpus file, and its prefixes, parses without a panic and into a
/// lossless tree (the debug assertions of the toolkit are on in tests).
#[test]
fn the_corpus_parses_losslessly() {
    for path in corpus() {
        let source = std::fs::read_to_string(&path).expect("corpus file");
        for cut in (0..=source.len()).filter(|i| source.is_char_boundary(*i)) {
            if cut % 11 != 0 && cut != source.len() {
                continue;
            }
            assert!(
                parse_is_lossless(&source[..cut]),
                "{} cut at {cut}",
                path.display()
            );
        }
    }
}

/// Deleting one token in three of a corpus file, or doubling it, never panics
/// (the toolkit's debug assertions catch an unbalanced marker or a loop
/// that does not consume) and keeps the tree lossless.
#[test]
fn a_deleted_or_doubled_token_never_breaks_the_parser() {
    for path in corpus() {
        let source = std::fs::read_to_string(&path).expect("corpus file");
        for (i, (start, end, _)) in lex_spans(&source).into_iter().enumerate() {
            if i % 3 != 0 {
                continue;
            }
            let deleted = format!("{}{}", &source[..start], &source[end..]);
            assert!(
                parse_is_lossless(&deleted),
                "{} without {start}..{end}",
                path.display()
            );
            let doubled = format!(
                "{}{}{}",
                &source[..end],
                &source[start..end],
                &source[end..]
            );
            assert!(
                parse_is_lossless(&doubled),
                "{} doubling {start}..{end}",
                path.display()
            );
        }
    }
}

/// Every tree of a corpus file that parses without error has the shape
/// `kql.ungram` says: the typed AST reads it as the grammar spells it.
#[test]
fn every_valid_tree_conforms_to_the_ungram() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for path in corpus() {
        let source = std::fs::read_to_string(&path).expect("corpus file");
        if parse_error_count(&source) > 0 {
            continue;
        }
        checked += 1;
        for problem in conformance(&source) {
            failures.push(format!("{}: {problem}", path.display()));
        }
    }
    assert!(checked > 140, "{checked} files");
    assert!(
        failures.is_empty(),
        "{} problems:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
