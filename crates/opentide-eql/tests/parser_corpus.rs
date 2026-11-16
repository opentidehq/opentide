//! The parser on every EQL file of the corpora: it reads the source the tree-sitter engine reads
//! (the engine it replaces), every tree is lossless, a file tree-sitter parses without an error
//! parses without one, and a file it rejects is rejected; the same for every line of a file.
//! The parser is private to the crate until the switch, so this test includes its source.

#![expect(dead_code, reason = "the included modules are used in part")]
#![expect(clippy::expect_used, reason = "a test")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/lexical.rs"]
mod lexical;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_core::LanguageId;
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

/// Whether tree-sitter finds a syntax error (on the text it parses: the nested comments
/// blanked).
fn tree_sitter_rejects(source: &str) -> bool {
    let prepared = lexical::prepare(source);
    let tree = opentide_syntax::parse(LanguageId::Eql, &prepared.text).expect("tree");
    opentide_syntax::has_error(&tree)
}

fn verdicts_match(source: &str) -> Result<(), String> {
    let parse = parser::parse(source);
    let root = syntax::SyntaxNode::new_root(parse.green.clone());
    if root.text() != source {
        return Err("the tree is not lossless".to_owned());
    }
    let old = tree_sitter_rejects(source);
    let new = !parse.errors.is_empty();
    if old == new {
        Ok(())
    } else {
        Err(format!(
            "tree-sitter {}, the parser {}",
            if old { "rejects" } else { "accepts" },
            if new {
                format!("rejects ({})", parse.errors[0].message)
            } else {
                "accepts".to_owned()
            }
        ))
    }
}

#[test]
fn every_file_and_line_keeps_its_verdict() {
    let files = eql_files();
    assert!(files.len() > 150, "{} files", files.len());
    let mut bad = Vec::new();
    let mut valid = 0;
    for path in &files {
        let source = std::fs::read_to_string(path).expect("read");
        let units = std::iter::once(source.as_str()).chain(source.lines());
        for unit in units {
            match verdicts_match(unit) {
                Ok(()) => valid += usize::from(!tree_sitter_rejects(unit)),
                Err(why) => bad.push(format!("{}: {unit:?}: {why}", path.display())),
            }
        }
    }
    assert!(bad.is_empty(), "{} differ:\n{}", bad.len(), bad.join("\n"));
    assert!(valid > 300, "{valid} valid inputs");
}

/// Hand-written cases of each construct, valid and broken.
#[test]
fn constructs_keep_their_verdict() {
    let cases = [
        "process where true",
        "any where a == 1 or b == 2 and not c",
        "process where a == b == c",
        // A comparison does not take a looser run as its operand (#1408 review).
        "process where a and b == c == d",
        "process where a or b < c < d",
        "process where a and not b == c == d",
        "process where a and descendant of [x where y] == 1",
        "process where f(a or b == c != d)",
        "process where a and x of [x where y] + 1",
        "process where a + b == c",
        "process where a * b + c == d and e or f",
        "process where a + b * c - d < e",
        "process where not a == 1",
        "process where a == not b",
        "process where -a * b + c % d - e / f",
        "process where - - a",
        "process where a in (1, 2, \"x\")",
        "process where a not in (1)",
        "process where a not : \"x\"",
        "process where a in~ (\"x\")",
        "process where a like~ (\"x\", \"y\")",
        "process where a regex \"x.*\"",
        "process where a : b",
        "process where a : (1, b)",
        "process where (a) : \"x\"",
        "process where a in ()",
        "process where f()",
        "process where f(a, b",
        "process where startsWith~(a, \"b\")",
        "process where in~(a)",
        "process where ?a.b[0].`c d` == 1",
        "process where a. == 1",
        "process where a.and == 1",
        "process where descendant of [process where true]",
        "process where descendant of [process where true] == 1",
        "process where not descendant of [process where true]",
        "process where a == descendant of [process where true]",
        "\"process\" where true",
        "PROCESS where true",
        "process where",
        "where true",
        "process true",
        "sequence [a where true] [b where true]",
        "sequence by a, b with maxspan=1m [a where true] by c [b where true] by d until [c where true]",
        "sequence with maxspan=5 by a [a where true] [b where true]",
        "sequence with maxspan=m [a where true]",
        "sequence [a where true] with runs=2 [b where true]",
        "sequence [a where true] with runs= [b where true]",
        "sequence ![a where true] [b where true]",
        "sequence",
        "sequence by",
        "sample by a [a where true] [b where true]",
        "sample [a where true] by x",
        "join by a [a where true] [b where true] until [c where true]",
        "join [a where true]",
        "process where true | head 5 | tail 1",
        "process where true | unique a, b",
        "process where true |",
        "process where true | head 5 6",
        "| head 1",
        "",
        "  // only a comment\n",
        "process where a == 1 )",
        "process where (a == 1",
        "process where [a where true]",
        "sequence [a where true] [b where true",
        "sequence [a where true]] [b where true]",
    ];
    let bad: Vec<String> = cases
        .iter()
        .filter_map(|c| verdicts_match(c).err().map(|why| format!("{c:?}: {why}")))
        .collect();
    assert!(bad.is_empty(), "{} differ:\n{}", bad.len(), bad.join("\n"));
}
