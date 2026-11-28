//! The parser on every EQL file of the corpora and every line of one (every tree is lossless),
//! and on hand-written cases of each construct, which keep the verdicts the tree-sitter engine
//! gave them when the parser replaced it.

use opentide_eql::{parser, syntax};

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

fn lossless(source: &str) -> bool {
    let parse = parser::parse(source);
    syntax::SyntaxNode::new_root(parse.green.clone()).text() == source
}

fn rejects(source: &str) -> bool {
    !parser::parse(source).errors.is_empty()
}

/// Every tree is lossless, of every file and of every line of one.
#[test]
fn every_file_and_line_parses_losslessly() {
    let files = eql_files();
    assert!(files.len() > 150, "{} files", files.len());
    for path in &files {
        let source = std::fs::read_to_string(path).expect("read");
        for unit in std::iter::once(source.as_str()).chain(source.lines()) {
            assert!(lossless(unit), "{}: {unit:?}", path.display());
        }
    }
}

/// Hand-written cases of each construct, valid and broken: `(source, the parser rejects it)`.
#[test]
fn constructs_keep_their_verdict() {
    let cases = [
        ("process where true", false),
        ("any where a == 1 or b == 2 and not c", false),
        ("process where a == b == c", true),
        // A comparison does not take a looser run as its operand (#1408 review).
        ("process where a and b == c == d", true),
        ("process where a or b < c < d", true),
        ("process where a and not b == c == d", true),
        ("process where a and descendant of [x where y] == 1", true),
        ("process where f(a or b == c != d)", true),
        ("process where a and x of [x where y] + 1", true),
        ("process where a + b == c", false),
        ("process where a * b + c == d and e or f", false),
        ("process where a + b * c - d < e", false),
        ("process where not a == 1", false),
        ("process where a == not b", true),
        ("process where -a * b + c % d - e / f", false),
        ("process where - - a", false),
        ("process where a in (1, 2, \"x\")", false),
        ("process where a not in (1)", false),
        ("process where a not : \"x\"", true),
        ("process where a in~ (\"x\")", false),
        ("process where a like~ (\"x\", \"y\")", false),
        ("process where a regex \"x.*\"", false),
        ("process where a : b", true),
        ("process where a : (1, b)", true),
        ("process where (a) : \"x\"", false),
        ("process where a in ()", true),
        ("process where f()", false),
        ("process where f(a, b", true),
        ("process where startsWith~(a, \"b\")", false),
        ("process where in~(a)", false),
        ("process where ?a.b[0].`c d` == 1", false),
        ("process where a. == 1", true),
        ("process where a.and == 1", true),
        ("process where descendant of [process where true]", false),
        (
            "process where descendant of [process where true] == 1",
            true,
        ),
        (
            "process where not descendant of [process where true]",
            false,
        ),
        (
            "process where a == descendant of [process where true]",
            true,
        ),
        ("\"process\" where true", false),
        ("PROCESS where true", false),
        ("process where", true),
        ("where true", true),
        ("process true", true),
        ("sequence [a where true] [b where true]", false),
        (
            "sequence by a, b with maxspan=1m [a where true] by c [b where true] by d until [c where true]",
            false,
        ),
        (
            "sequence with maxspan=5 by a [a where true] [b where true]",
            false,
        ),
        ("sequence with maxspan=m [a where true]", true),
        ("sequence [a where true] with runs=2 [b where true]", false),
        ("sequence [a where true] with runs= [b where true]", true),
        ("sequence ![a where true] [b where true]", false),
        ("sequence", true),
        ("sequence by", true),
        ("sample by a [a where true] [b where true]", false),
        ("sample [a where true] by x", false),
        (
            "join by a [a where true] [b where true] until [c where true]",
            false,
        ),
        ("join [a where true]", true),
        ("process where true | head 5 | tail 1", false),
        ("process where true | unique a, b", false),
        ("process where true |", true),
        ("process where true | head 5 6", true),
        ("| head 1", true),
        ("", false),
        ("  // only a comment\n", false),
        ("process where a == 1 )", true),
        ("process where (a == 1", true),
        ("process where [a where true]", true),
        ("sequence [a where true] [b where true", true),
        ("sequence [a where true]] [b where true]", true),
    ];
    for (case, rejected) in cases {
        assert!(lossless(case), "{case:?}");
        assert_eq!(rejects(case), rejected, "{case:?}");
    }
}
