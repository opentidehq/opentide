//! The parser's trees as snapshots: one tree per corpus file (valid and invalid alike) and the
//! recovery cases, each with its errors. A changed tree is a reviewed snapshot diff.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_parse::{debug_errors, debug_tree};
use syntax::{Lang, SyntaxKind};

/// The tree and the errors of `source`, as text.
fn debug_parse(source: &str) -> String {
    let (root, parse) = parser::parse(source);
    let tree = debug_tree::<Lang, _>(&root, |kind| format!("{kind:?}"));
    let errors = debug_errors(&parse.errors, |kind| {
        format!("{:?}", SyntaxKind::from_raw(kind))
    });
    format!("{tree}\n{errors}")
}

/// The query of a corpus file: the `# prod:<rule>` tag on its first line is not part of it.
fn query(file: &str) -> &str {
    match file.split_once('\n') {
        Some((tag, rest)) if tag.starts_with("# prod:") => rest,
        _ => file,
    }
}

#[test]
fn corpus_trees() {
    insta::glob!("../../testdata/corpus/cql", "*.cql", |path| {
        let file = std::fs::read_to_string(path).expect("a corpus file");
        insta::assert_snapshot!(debug_parse(query(&file)));
    });
}

/// Precedence, juxtaposition and the rule that a call is never a filter operand.
#[test]
fn precedence_and_steps() {
    for (name, source) in [
        ("not_binds_tightest", "foo and not bar or baz"),
        ("juxtaposition_is_and", "src=\"client\" ip=127.0.0.1 or x=1"),
        ("flat_or_run", "a or b or c or d"),
        ("flat_binary_run", "x := a + b - c * d / e"),
        ("assignment_then_call", "x := 1 y := 2 count()"),
        ("filter_then_call", "ERROR groupBy(host)"),
        ("case_with_branches", "case { a=1 | x := 1 ; b=2 ; * }"),
        (
            "match_with_guards",
            "x match { \"a\" => y := 1 ; * => y := 2 }",
        ),
        ("saved_query", "$\"my query\"(a=?b, c=[d, e])"),
        (
            "correlate",
            "correlate(a: { x=1 } include: [k], b: { y=2 | q <=> a.k }, within=5m)",
        ),
        ("regex_and_flags", "a=/x\\/y[/]z/i"),
        ("parameter_with_default", "a=?{b=c} d like ?\"e f\""),
    ] {
        insta::assert_snapshot!(name, debug_parse(source));
    }
}

/// Recovery: one error where tree-sitter has one, and the rest of the input still in a tree.
#[test]
fn recovery() {
    for (name, source) in [
        ("unclosed_paren", "(a=1 or b=2"),
        ("unclosed_brace", "f({ a=1 | b=2 )"),
        ("stray_close", "a=1 ) b=2"),
        ("dangling_or", "a=1 or"),
        ("dangling_and", "a=1 and | b"),
        ("empty_step", "a=1 | | b=2"),
        ("trailing_pipe_nested", "f({ a=1 | })"),
        ("filter_after_assignment", "x := 1 y"),
        ("negated_call_after_filter", "foo !in(x)"),
        ("missing_value", "a="),
        ("missing_regex_close", "a=/abc"),
        ("saved_query_space", "$q (a=b)"),
        ("call_as_operand", "a and f()"),
        ("empty_match", "x match { }"),
        ("match_guard_without_arrow", "x match { a }"),
        ("double_unary", "x := !!a"),
    ] {
        insta::assert_snapshot!(name, debug_parse(source));
    }
}

/// The review's noisy recoveries: each of these is one error, and an empty step expects no
/// `|` (it found one).
#[test]
fn one_error_per_fault() {
    for source in [
        "x match { }",
        "x match { a }",
        "x := !!a",
        "x := - - a",
        "a=1 | | b=2",
    ] {
        let (_, parse) = parser::parse(source);
        assert_eq!(parse.errors.len(), 1, "{source}: {:?}", parse.errors);
    }
    let (_, parse) = parser::parse("a=1 | | b=2");
    assert!(
        !parse.errors[0]
            .expected
            .contains(syntax::SyntaxKind::PIPE.raw()),
        "{:?}",
        parse.errors
    );
}

/// Past `max_depth` the rest of the input is one error node and one error (not snapshotted:
/// the node holds every token).
#[test]
fn too_deep_is_one_error() {
    let (_, parse) = parser::parse(&"(".repeat(2_000));
    let deep = parse
        .errors
        .iter()
        .filter(|e| matches!(e.kind, opentide_parse::ErrorKind::TooDeep { .. }))
        .count();
    assert_eq!(deep, 1, "{:?}", parse.errors);
}
