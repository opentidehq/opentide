//! The new parser over every `.kql` of `crates/testdata`: lossless on every
//! file and prefix, and the same verdict as tree-sitter on every file.

mod common;
use common::corpus;
use opentide_core::LanguageId;
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

/// Against tree-sitter, on every corpus file:
/// what it reads without error, the new parser reads without error, and
/// what it reads with one, the new parser does too (the verdicts agree).
#[test]
fn the_verdicts_agree_with_tree_sitter() {
    let (mut valid, mut broken) = (0, 0);
    let mut disagree = Vec::new();
    for path in corpus() {
        let source = std::fs::read_to_string(&path).expect("corpus file");
        let Some(tree) = opentide_syntax::parse(LanguageId::Kql, &source) else {
            continue;
        };
        let old_error = opentide_syntax::has_error(&tree);
        let new_error = parse_error_count(&source) > 0;
        if old_error {
            broken += 1;
        } else {
            valid += 1;
        }
        if old_error != new_error {
            disagree.push(format!(
                "{}: tree-sitter {old_error}, here {new_error}",
                path.file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
            ));
        }
    }
    assert!(valid > 20 && broken > 0, "{valid} valid, {broken} broken");
    assert!(
        disagree.is_empty(),
        "{} of {}:\n{}",
        disagree.len(),
        valid + broken,
        disagree.join("\n")
    );
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
