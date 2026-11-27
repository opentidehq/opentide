//! The parser over every CQL file of the corpora: the tree holds every byte, no toolkit
//! guard fires, and the pinned regressions keep their verdicts.

use opentide_cql::parser;

use opentide_parse::ErrorKind;
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

fn ours_fails(source: &str) -> bool {
    !parser::parse(source).1.errors.is_empty()
}

/// The tree is lossless: its text is the source.
#[test]
fn the_tree_holds_every_byte_of_every_corpus_file() {
    for path in corpus() {
        let file = std::fs::read_to_string(&path).unwrap_or_default();
        let source = query(&file);
        let (root, _) = parser::parse(source);
        assert_eq!(root.text().to_string(), source, "{}", path.display());
    }
}

/// Nothing the parser reports is a toolkit guard on a small input.
#[test]
fn no_guard_fires_on_small_inputs() {
    for path in corpus() {
        let file = std::fs::read_to_string(&path).unwrap_or_default();
        let (_, tree) = parser::parse(query(&file));
        assert!(
            tree.errors.iter().all(|e| e.kind == ErrorKind::Syntax),
            "{}",
            path.display()
        );
    }
}

/// Inputs the mutation runs against tree-sitter found the parser getting wrong, each reduced
/// to a minimal source: `(source, the parser reports an error)`. Each fails without the fix
/// it pins.
#[test]
fn pinned_regressions() {
    for (source, fails) in [
        // A negated call, `match`, `<=>` after a filter are filters there, and fail.
        ("foo !in(x)", true),
        ("foo | !in(x)", false),
        ("foo not in(x)", true),
        ("foo x match { * => a }", true),
        // `%` is an operator after an operand.
        ("x := (p * 1) % t", false),
        // A saved query's `(` and a parameter's name touch the sigil.
        ("$q (a=b)", true),
        ("? \"x\"", true),
        // The scanner reads any word before `:=` as an assignment field.
        ("#type OR:= \"fortigate\"", false),
        ("case := (@timestamp)", false),
        ("x a like := 1", false),
        // After a filter only a plain word starts an assignment.
        ("ERROR \"Success\":= \"fortigate\"", true),
        ("upperhost a[0]:= upper", true),
        ("a b := 1", false),
        // A call after an assignment's parenthesised value, then a filter.
        ("x := (a + b)f(a1, b) *", false),
        // `true` and `false` are keywords, not names.
        ("true = x", true),
        ("a=~f(true=1)", true),
        ("f(a: { }, false: { })", true),
        // `case` is a word inside parentheses.
        ("(x case )", false),
        // A reserved word is no parameter default.
        ("?{a=and}", true),
        // A comment longer than a saved query name wins.
        ("f({$/*x y()}, a)\n/* c */", true),
    ] {
        assert_eq!(ours_fails(source), fails, "the parser on {source:?}");
    }
}
