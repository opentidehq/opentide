//! The typed AST of `cql.ungram` (`src/generated/ast.rs`, written by `cargo xtask codegen`,
//! kept current by `codegen --check`) and its conformance: every tree of the corpus that
//! parses without an error has the shape the `.ungram` states, node by node.

use opentide_cql::{ast, parser};

use opentide_parse::ast::AstNode;
use opentide_parse::conformance::{assert_conforms, check};
use std::path::{Path, PathBuf};

/// Every `.cql` file under `crates/testdata`.
fn corpus() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "cql") {
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

/// The query of a corpus file: the `# prod:<rule>` tag on its first line is not part of it.
fn query(file: &str) -> &str {
    match file.split_once('\n') {
        Some((tag, rest)) if tag.starts_with("# prod:") => rest,
        _ => file,
    }
}

#[test]
fn every_corpus_tree_conforms_to_the_ungram() {
    let (mut checked, mut bad) = (0, Vec::new());
    for path in corpus() {
        let file = std::fs::read_to_string(&path).unwrap_or_default();
        let (root, parse) = parser::parse(query(&file));
        if !parse.errors.is_empty() {
            continue;
        }
        for mismatch in check(&root, ast::RULES, parser::GRAMMAR) {
            bad.push(format!("{}: {mismatch}", path.display()));
        }
        checked += 1;
    }
    assert!(
        bad.is_empty(),
        "{} mismatches:\n{}",
        bad.len(),
        bad.join("\n")
    );
    assert!(checked > 100, "checked {checked} trees");
}

#[test]
fn the_accessors_reach_a_filter_and_a_call() {
    let (root, parse) = parser::parse("ip=1.2.3.4 | groupBy([a], function=count())");
    assert!(parse.errors.is_empty());
    assert_conforms(&root, ast::RULES, parser::GRAMMAR);
    let file = ast::SourceFile::cast(root).expect("a source file");
    let pipeline = file.pipeline().expect("a pipeline");
    assert_eq!(pipeline.syntax().children().count(), 2);
}

/// Trees of generated valid queries (corpus files joined by a pipe, and every prefix of a
/// line that parses) conform too, not only the files themselves.
#[test]
fn trees_of_joined_and_truncated_queries_conform() {
    let files: Vec<String> = corpus()
        .iter()
        .map(|p| query(&std::fs::read_to_string(p).unwrap_or_default()).to_owned())
        .collect();
    let mut inputs = Vec::new();
    for (i, a) in files.iter().enumerate() {
        let b = &files[(i * 7 + 3) % files.len()];
        inputs.push(format!("{a}\n| {b}"));
        for line in a.lines().take(40) {
            inputs.push(line.to_owned());
            if let Some((head, _)) = line.rsplit_once(' ') {
                inputs.push(head.to_owned());
            }
        }
    }
    let (mut checked, mut bad) = (0, Vec::new());
    for source in inputs {
        let (root, parse) = parser::parse(&source);
        if !parse.errors.is_empty() {
            continue;
        }
        for mismatch in check(&root, ast::RULES, parser::GRAMMAR) {
            bad.push(format!("{source:?}: {mismatch}"));
        }
        checked += 1;
    }
    assert!(
        bad.is_empty(),
        "{} mismatches:\n{}",
        bad.len(),
        bad[..bad.len().min(10)].join("\n")
    );
    assert!(checked > 500, "checked {checked} trees");
}
