//! The new lexer over every `.kql` of `crates/testdata`: lossless, and
//! token for token what tree-sitter reads on the files it reads cleanly.

use opentide_core::LanguageId;
use opentide_kql::testing::lex_spans;
mod common;
use common::corpus;

/// Every byte of every corpus file, and of prefixes of it, is in one
/// lexeme (the lexer is lossless).
#[test]
fn lexing_is_lossless_over_the_corpus() {
    let files = corpus();
    assert!(files.len() > 150, "{} files", files.len());
    for path in files {
        let source = std::fs::read_to_string(&path).expect("corpus file");
        for cut in (0..=source.len()).filter(|i| source.is_char_boundary(*i)) {
            if cut % 7 != 0 && cut != source.len() {
                continue;
            }
            let text = &source[..cut];
            let mut end = 0;
            for (start, stop, _) in lex_spans(text) {
                assert_eq!(start, end, "{} cut at {cut}", path.display());
                end = stop;
            }
            assert_eq!(end, text.len(), "{} cut at {cut}", path.display());
        }
    }
}

/// The byte ranges of the leaves of the tree-sitter tree, comments apart.
fn leaves(node: tree_sitter::Node, out: &mut Vec<(usize, usize)>) {
    if node.child_count() == 0 {
        if node.kind() != "comment" && node.end_byte() > node.start_byte() {
            out.push((node.start_byte(), node.end_byte()));
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        leaves(child, out);
    }
}

/// On every corpus file tree-sitter reads without error, the new lexer's
/// tokens are the tree-sitter tokens, but for the glued ones the parser
/// puts back together (`Foo*`, a column pattern, is one tree-sitter token
/// and two here; the test folds them).
#[test]
fn the_tokens_are_the_tree_sitter_tokens_on_valid_files() {
    let mut different = Vec::new();
    let mut checked = 0;
    for path in corpus() {
        let source = std::fs::read_to_string(&path).expect("corpus file");
        let Some(tree) = opentide_syntax::parse(LanguageId::Kql, &source) else {
            continue;
        };
        if opentide_syntax::has_error(&tree) {
            continue;
        }
        checked += 1;
        let mut old = Vec::new();
        leaves(tree.root_node(), &mut old);
        let mut new: Vec<(usize, usize)> = Vec::new();
        for (start, end, _) in lex_spans(&source).into_iter().filter(|s| !s.2) {
            // Fold the pieces of a glued column pattern into its token.
            match old.iter().find(|&&(s, e)| {
                s <= start && end <= e && e - s > end - start && source[s..e].contains('*')
            }) {
                Some(&whole) => {
                    if new.last() != Some(&whole) {
                        new.push(whole);
                    }
                }
                None => new.push((start, end)),
            }
        }
        if old != new {
            let at = old
                .iter()
                .zip(&new)
                .position(|(a, b)| a != b)
                .unwrap_or(old.len().min(new.len()));
            different.push(format!(
                "{}: token {at}: tree-sitter {:?}, here {:?}",
                path.display(),
                old.get(at).map(|&(s, e)| &source[s..e]),
                new.get(at).map(|&(s, e)| &source[s..e]),
            ));
        }
    }
    assert!(checked > 100, "{checked} files");
    assert!(
        different.is_empty(),
        "{} of {checked}:\n{}",
        different.len(),
        different.join("\n")
    );
}
