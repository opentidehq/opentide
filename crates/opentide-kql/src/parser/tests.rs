//! Tree snapshots of the productions, error recovery and depth. The corpus
//! tests are in `tests/parser_corpus.rs`.

use super::parse;
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_parse::{ErrorKind, debug_errors, debug_tree};

/// The tree and the errors of `source`, as the snapshots show them.
fn show(source: &str) -> String {
    let parsed = parse(source);
    let tree = SyntaxNode::new_root(parsed.green);
    assert_eq!(tree.to_string(), source, "the tree is lossless");
    let mut out = debug_tree(&tree, |k| format!("{k:?}"));
    let errors = debug_errors(&parsed.errors, |k| K::from_raw(k).describe());
    if !errors.is_empty() {
        out.push_str("errors:\n");
        out.push_str(&errors);
    }
    out
}

fn errors(source: &str) -> Vec<String> {
    parse(source)
        .errors
        .into_iter()
        .map(|e| e.message)
        .collect()
}

macro_rules! snapshots {
    ($($name:ident: $source:expr;)*) => {$(
        #[test]
        fn $name() {
            insta::assert_snapshot!(show($source));
        }
    )*};
}

snapshots! {
    let_scalar: "let x = 1;\nlet y = a + 1;\nT";
    let_table_and_call: "let x = T;\nlet y = f(1);\nlet z = (T | take 1);\nT";
    let_function: "let f = (a: int, t: (*), u: (c: string, d: dynamic) = 1) { let y = 2; T | take 5 };\nf(1, 2)";
    control_command: ".show tables details";
    precedence: "T | where a or b and not c has \"x\" or d == 1 + 2 * 3 - 4";
    flat_chain: "T | where a or b or c or d";
    sign_and_literals: "T | where x == -1 and y == 5m and z == datetime(2024-01-01) and w == null and v == True";
    member_and_index: "T | where a.b[0].c == d[\"k\"] and e.[\"x.y\"] == f['q']['r']";
    calls: "T | where f(a, b = 1, *) and g() and count() > 0 and not(a == b)";
    sets_and_ranges: "T | where a in (1, 2) and b !in~ (\"x\") and c between (1 .. 3) and d matches regex \"x\" and e in (T2 | project x)";
    dynamic_and_toscalar: "T | where a == dynamic([1, -2, \"x\", {\"k\": [true, null],}]) and b == toscalar(U | count) and c == dynamic(null)";
    keywords_are_names: "T | where by == on and has != count and kind has_any (1)";
    unknown_operator: "T | frobnicate a";
    quoted_names: "let n = 1;\nT | where ['a b'] == n";
}

snapshots! {
    error_missing_operand: "T | where a ==";
    error_missing_semicolon: "let x = 1\nT";
    error_unclosed_paren: "T | where (a";
    error_not_not: "T | where not not a";
    error_double_sign: "T | where --a";
    error_comparison_chain: "T | where a == b == c";
    error_trailing_input: "T | take 5 )";
    error_empty_call_argument: "T | where f(a,)";
    error_unclosed_function: "let f = () { T ;\nf()";
}

#[test]
fn an_empty_source_and_a_comment_are_valid() {
    assert!(errors("").is_empty());
    assert!(errors("// nothing\n").is_empty());
}

#[test]
fn a_long_chain_is_flat_and_parses() {
    let source = format!("T | where {}", vec!["a == 1"; 20_000].join(" or "));
    let parsed = parse(&source);
    assert!(parsed.errors.is_empty());
    assert!(parsed.depth < 20, "{} levels", parsed.depth);
}

#[test]
fn nesting_up_to_the_limit_parses_and_past_it_is_one_error() {
    let nest = |n: usize| format!("T | where {}a == 1{}", "(".repeat(n), ")".repeat(n));
    assert!(parse(&nest(200)).errors.is_empty());
    let deep = parse(&nest(5_000));
    assert_eq!(deep.errors.len(), 1, "{:?}", deep.errors);
    assert!(matches!(deep.errors[0].kind, ErrorKind::TooDeep { .. }));
}

#[test]
fn a_long_member_chain_does_not_overflow() {
    let source = format!("T | where {}", vec!["a"; 10_000].join("."));
    let _ = parse(&source);
}
