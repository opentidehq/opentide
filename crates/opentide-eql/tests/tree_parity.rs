//! The analysis's tree (`src/tree.rs`) against the tree-sitter tree it stands in for, node by
//! node (kind, named, span, field, place), on every EQL file of the corpora and every line of
//! one, wherever tree-sitter parses the text without an error.

#![expect(dead_code, reason = "the included modules are used in part")]
#![expect(clippy::expect_used, reason = "a test")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "legacy/lexical.rs"]
mod lexical;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;
#[path = "../src/tree.rs"]
mod tree;

/// What `tree.rs` reads from the crate root.
const KEYWORD_WORDS: &[&str] = &[
    "and", "any", "by", "false", "in", "join", "like", "maxspan", "not", "null", "of", "or",
    "regex", "sample", "sequence", "true", "until", "where", "with",
];

use opentide_core::LanguageId;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn eql_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "eql") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut out,
    );
    out.sort();
    out
}

/// Tree-sitter's tree, one line per node, or `None` when it has an error.
fn old(source: &str) -> Option<String> {
    let prepared = lexical::prepare(source);
    let tree = opentide_syntax::parse(LanguageId::Eql, &prepared.text).expect("tree");
    if opentide_syntax::has_error(&tree) {
        return None;
    }
    let mut out = String::new();
    let mut cursor = tree.walk();
    let mut depth = 0;
    loop {
        let node = cursor.node();
        let _ = writeln!(
            out,
            "{}{} {} {}..{} {:?}",
            "  ".repeat(depth),
            node.kind(),
            node.is_named(),
            node.start_byte(),
            node.end_byte(),
            cursor.field_name()
        );
        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Some(out);
            }
            depth -= 1;
        }
    }
}

/// The analysis's tree, in the same form.
fn new(source: &str) -> String {
    let tree = tree::parse(source);
    let mut out = String::new();
    tree::walk_with_ancestors(tree.root_node(), |node, ancestors| {
        let _ = writeln!(
            out,
            "{}{} {} {}..{} {:?}",
            "  ".repeat(ancestors.len()),
            node.kind(),
            node.is_named(),
            node.start_byte(),
            node.end_byte(),
            node.field_name()
        );
    });
    out
}

#[test]
fn the_tree_is_tree_sitters_on_every_valid_file_and_line() {
    let mut compared = 0;
    let mut bad = Vec::new();
    for path in eql_files() {
        let source = std::fs::read_to_string(&path).expect("read");
        for unit in std::iter::once(source.as_str()).chain(source.lines()) {
            let Some(expected) = old(unit) else {
                continue;
            };
            compared += 1;
            let found = new(unit);
            if found != expected {
                let line = found
                    .lines()
                    .zip(expected.lines())
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                bad.push(format!(
                    "{}: {unit:?}\n  first difference at node {line}:\n  new: {:?}\n  old: {:?}",
                    path.display(),
                    found.lines().nth(line),
                    expected.lines().nth(line)
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} differ:\n{}",
        bad.len(),
        bad.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(compared > 300, "{compared} compared");
}
