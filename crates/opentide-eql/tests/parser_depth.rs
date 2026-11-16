//! The parser's depth guards, on the 1 MB stack of the browser module: the floors
//! `crates/opentide-analysis/tests/deep_queries.rs` holds for EQL (1,000 nesting levels, a
//! 20,000-term chain) parse without a diagnostic, every construct that recurses survives deeper
//! nesting as one diagnostic, never an overflow, and chains stay flat. The parser is private to
//! the crate until the switch, so this test includes its source.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_parse::{ErrorKind, MAX_TREE_DEPTH};

/// Parses on a 1 MB stack, drops the tree there too; the errors' kinds and the tree's depth.
fn parse_small(source: String) -> (Vec<ErrorKind>, usize) {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let parse = parser::parse(&source);
            let root = syntax::SyntaxNode::new_root(parse.green);
            assert_eq!(root.text().len(), rowan::TextSize::of(source.as_str()));
            (parse.errors.iter().map(|e| e.kind).collect(), parse.depth)
        })
        .map(std::thread::JoinHandle::join)
        .unwrap_or_else(|e| panic!("spawn: {e}"))
        .unwrap_or_else(|_| panic!("the parser overflowed or panicked"))
}

fn query(expr: &str) -> String {
    format!("process where {expr}")
}

#[test]
fn the_floors_parse_without_a_diagnostic() {
    let n = 1_000;
    let nest = query(&format!("{}a == 1{}", "(".repeat(n), ")".repeat(n)));
    assert_eq!(parse_small(nest).0, []);
    let limit = usize::try_from(parser::MAX_DEPTH).unwrap_or(usize::MAX);
    // At the limit, the innermost operand is one with no operator (`a == 1` is one level more).
    let at_limit = query(&format!("{}a{}", "(".repeat(limit), ")".repeat(limit)));
    assert_eq!(parse_small(at_limit).0, []);
    for (op, term) in [
        (" or ", "a == 1"),
        (" and ", "a == 1"),
        (" + ", "a"),
        (" * ", "a"),
        (" % ", "a"),
    ] {
        let (errors, depth) = parse_small(query(&vec![term; 20_000].join(op)));
        assert_eq!(errors, [], "{op}");
        assert!(depth < 10, "{op}: depth {depth}");
    }
    let (errors, depth) = parse_small(query(&vec!["a"; 20_000].join(" - ")));
    assert_eq!(errors, []);
    assert!(depth < 10, "depth {depth}");
}

/// Every construct that recurses, closed, at the nesting floor and at the limit: no diagnostic
/// and no overflow. Nested calls overflowed a 1 MB stack before the recursive rules' frames
/// were trimmed (1,065 bytes a level in a debug build; now about 715).
#[test]
fn every_recursive_construct_parses_to_the_limit() {
    let limit = usize::try_from(parser::MAX_DEPTH).unwrap_or(usize::MAX);
    for n in [1_000, limit] {
        let wrap =
            |open: &str, close: &str| query(&format!("{}1{}", open.repeat(n), close.repeat(n)));
        let cases = [
            wrap("(", ")"),
            wrap("f(", ")"),
            wrap("f~(", ")"),
            wrap("not ", ""),
            wrap("- ", ""),
            wrap("+", ""),
            wrap("a in (", ")"),
            wrap("a not in~ (", ")"),
            wrap("x of [any where ", "]"),
        ];
        for source in cases {
            let head: String = source.chars().take(40).collect();
            let (errors, _) = parse_small(source);
            assert_eq!(errors, [], "{n} {head}");
        }
    }
}

/// A pattern operator takes constants, so `a : (a : (...` does not nest: a few syntax errors,
/// not one per level.
#[test]
fn a_pattern_list_does_not_nest() {
    let (errors, _) = parse_small(query(&format!(
        "{}1{}",
        "a : (".repeat(5_000),
        ")".repeat(5_000)
    )));
    assert!(!errors.is_empty() && errors.len() <= 3, "{errors:?}");
}

#[test]
fn every_recursive_construct_is_one_diagnostic_past_the_limit() {
    for n in [1_100, 5_000, 100_000] {
        let wrap =
            |open: &str, close: &str| query(&format!("{}1{}", open.repeat(n), close.repeat(n)));
        let cases = [
            wrap("(", ")"),
            wrap("(", ""),
            wrap("f(", ")"),
            wrap("f(", ""),
            wrap("not ", ""),
            wrap("- ", ""),
            wrap("+", ""),
            wrap("a in (", ")"),
            wrap("f(1, (", "))"),
            wrap("x of [any where ", "]"),
            format!("sequence {}", "[any where x of ".repeat(n)),
        ];
        for source in cases {
            let head: String = source.chars().take(40).collect();
            let (errors, depth) = parse_small(source);
            let deep = errors
                .iter()
                .filter(|e| matches!(e, ErrorKind::TooDeep { .. }))
                .count();
            assert_eq!(deep, 1, "{n} {head}: {errors:?}");
            assert!(depth < MAX_TREE_DEPTH, "{n} {head}: depth {depth}");
        }
    }
}

/// Every operator level inside each parenthesis (`(a or b and c == d + e * (...`) recurses
/// through each level: each is a level of its own, so deep nesting of this shape is one
/// diagnostic, never an overflow, and shallow nesting parses (#1408 review).
#[test]
fn mixed_levels_inside_nesting_are_bounded() {
    let ladder = |n: usize| {
        query(&format!(
            "{}1{}",
            "(a or b and c == d + e * ".repeat(n),
            ")".repeat(n)
        ))
    };
    assert_eq!(parse_small(ladder(100)).0, []);
    for n in [170, 300, 900, 5_000] {
        let (errors, depth) = parse_small(ladder(n));
        let deep = errors
            .iter()
            .filter(|e| matches!(e, ErrorKind::TooDeep { .. }))
            .count();
        assert!(deep <= 1, "{n}: {errors:?}");
        assert!(depth < MAX_TREE_DEPTH, "{n}: depth {depth}");
    }
    let calls = query(&format!(
        "{}1{}",
        "a in (b or b and c == d + e * f(g or h and i == j + k * -".repeat(340),
        "))".repeat(340)
    ));
    let (errors, _) = parse_small(calls);
    assert!(
        errors
            .iter()
            .filter(|e| matches!(e, ErrorKind::TooDeep { .. }))
            .count()
            == 1,
        "{errors:?}"
    );
}
