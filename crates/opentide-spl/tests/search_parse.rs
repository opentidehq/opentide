//! The pipeline and search-term grammar of the pure-Rust parser against the
//! corpus: every valid file parses without an error and losslessly, a few
//! broken queries get the old parser's verdict, and the search fixtures'
//! trees are snapshots.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::LanguageId;
use opentide_parse::{debug_errors, debug_tree};
use opentide_spl::syntax::{Lang, SyntaxKind, parse};
use std::path::Path;

/// A fixture's text without its `prod:` tag line, as the baseline reads it.
fn body(path: &Path) -> String {
    let text = std::fs::read_to_string(path).expect("read");
    if path.components().any(|c| c.as_os_str() == "corpus") {
        text.lines().skip(1).collect::<Vec<_>>().join("\n")
    } else {
        text
    }
}

fn render(source: &str) -> String {
    let (tree, parse) = parse(source);
    assert_eq!(tree.to_string(), source, "lossless");
    let mut out = debug_tree(&tree, |k: SyntaxKind| format!("{k:?}"));
    out.push_str("--\n");
    out.push_str(&debug_errors(&parse.errors, |k| {
        format!("{:?}", <Lang as rowan::Language>::kind_from_raw(k))
    }));
    out
}

fn corpus() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/corpus/spl")
}

/// The old parser's verdict on `source`.
fn tree_sitter_accepts(source: &str) -> bool {
    let tree = opentide_syntax::parse(LanguageId::Spl, source).expect("parser");
    !opentide_syntax::has_error(&tree)
}

#[test]
fn every_search_fixture_is_a_snapshot() {
    let mut count = 0;
    insta::glob!(corpus(), "*.spl", |path| {
        let name = path.file_name().expect("name").to_string_lossy();
        let searchy = [
            "bare_search",
            "search_",
            "in_clause",
            "term_clause",
            "case_clause",
            "macro",
            "comment",
            "field_value",
        ]
        .iter()
        .any(|p| name.starts_with(p));
        if !searchy {
            return;
        }
        count += 1;
        insta::assert_snapshot!(render(&body(path)));
    });
    assert!(count > 15 || count == 0, "{count} fixtures");
}

#[test]
fn a_valid_fixture_has_no_error() {
    let mut checked = 0;
    for entry in std::fs::read_dir(corpus()).expect("dir") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        let source = body(&path);
        let (tree, parsed) = parse(&source);
        assert_eq!(tree.to_string(), source, "{name}: lossless");
        if name.contains("__valid") {
            assert!(parsed.errors.is_empty(), "{name}: {}", render(&source));
            checked += 1;
        }
    }
    assert!(checked > 60, "{checked} valid fixtures");
}

#[test]
fn the_old_parsers_search_verdicts_hold() {
    for query in [
        "index=main error",
        "a AND OR b",
        "a (b",
        "a b)",
        "NOT",
        "a OR",
        "index=main |",
        "[ search a |]",
        "a [ b ]",
    ] {
        let ours = parse(query).1.errors.is_empty();
        assert_eq!(
            ours,
            tree_sitter_accepts(query),
            "{query:?}: {}",
            render(query)
        );
    }
}
