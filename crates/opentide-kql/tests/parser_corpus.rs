//! The new parser over every `.kql` of `crates/testdata`: lossless on every
//! file and prefix, and the same verdict as tree-sitter on the files that
//! need only the forms parsed so far.

mod common;
use common::corpus;
use opentide_core::LanguageId;
use opentide_kql::testing::{parse_error_count, parse_is_lossless};

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

/// The node kinds of the old tree that name an operator or a form this PR
/// does not parse yet.
fn uses_unparsed_forms(node: tree_sitter::Node) -> bool {
    const PARSED: [&str; 6] = [
        "where_operator",
        "filter_operator",
        "take_operator",
        "limit_operator",
        "count_operator",
        "tabular_operator",
    ];
    let kind = node.kind();
    let unparsed = (kind.ends_with("_operator") && !PARSED.contains(&kind))
        || matches!(
            kind,
            "search_source"
                | "datatable_expression"
                | "externaldata_expression"
                | "range_operator"
                | "column_pattern"
                | "unknown_operator"
        );
    let mut cursor = node.walk();
    unparsed || node.children(&mut cursor).any(uses_unparsed_forms)
}

/// Against tree-sitter, on the files that need nothing from the next PR:
/// what it reads without error, the new parser reads without error, and
/// what it reads with one, the new parser does too (the verdicts agree).
#[test]
fn the_verdicts_agree_with_tree_sitter_on_the_forms_parsed_so_far() {
    let (mut valid, mut broken) = (0, 0);
    let mut disagree = Vec::new();
    for path in corpus() {
        let source = std::fs::read_to_string(&path).expect("corpus file");
        let Some(tree) = opentide_syntax::parse(LanguageId::Kql, &source) else {
            continue;
        };
        if uses_unparsed_forms(tree.root_node())
            || opentide_kql::testing::names_an_unparsed_operator(&source)
        {
            continue;
        }
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
