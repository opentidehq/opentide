//! `syntax::PRODUCTIONS`, the list the corpus gate requires a fixture for, against what the
//! parser builds on the files of `crates/testdata`. A test file, not a unit test: the crate's
//! sources stay free of I/O (`scripts/engine/check-io-free.sh`).

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

/// `syntax::PRODUCTIONS` is exactly what a parse builds: on every `.cql` file of
/// `crates/testdata`, valid or broken, the node kinds other than `ERROR`, and the two comment
/// tokens tree-sitter named. A production the parser grows, or one dropped from the list
/// (a comment included), fails here before the corpus gate can miss it.
#[test]
fn the_productions_are_what_a_parse_builds() {
    use std::collections::BTreeSet;
    use syntax::{PRODUCTIONS, SyntaxKind as K};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
    let mut stack = vec![root];
    let mut files = 0;
    let mut built = BTreeSet::new();
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
                .path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "cql") {
                continue;
            }
            files += 1;
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let (tree, _) = parser::parse(&text);
            for element in tree.descendants_with_tokens() {
                let kind = element.kind();
                let named = match element {
                    rowan::NodeOrToken::Node(_) => kind != K::ERROR,
                    rowan::NodeOrToken::Token(_) => {
                        matches!(kind, K::LINE_COMMENT | K::BLOCK_COMMENT)
                    }
                };
                if named {
                    assert!(
                        PRODUCTIONS.contains(&kind),
                        "{kind:?} in {}",
                        path.display()
                    );
                    built.insert(format!("{kind:?}"));
                }
            }
        }
    }
    assert!(files > 100, "{files} files");
    let listed: BTreeSet<String> = PRODUCTIONS.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(listed, built, "listed, never built on the corpus");
}
