//! The parser at its limits, on a 1 MB stack in a debug build (the browser WASM module's;
//! more on Windows and under coverage, [`SMALL_STACK`]):
//! every recursive construct parses at the nesting floor (1,000 levels) with no error, past
//! `max_depth` it is one `TooDeep` error and no overflow, and a long chain is flat.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_parse::ErrorKind;
use std::time::{Duration, Instant};

/// The nesting floor of `crates/opentide-analysis/tests/deep_queries.rs`.
const FLOOR: usize = 1_000;
/// The chain floor.
const CHAIN: usize = 20_000;

/// The stack the depth checks run on: the browser WASM module's 1 MB.
#[cfg(not(any(coverage, windows)))]
const SMALL_STACK: usize = 1 << 20;
/// A Windows debug build's frames are larger, and `cargo llvm-cov`'s
/// instrumentation enlarges every frame: the depths that fit 1 MB on Linux
/// overflowed the nightly's Windows engine tests. Neither binary is the WASM
/// budget, which the Linux and macOS test jobs keep enforcing at 1 MB; 8 MB is
/// a generous bound, not a measurement. The same rule as `SMALL_STACK` in
/// `crates/opentide-analysis/tests/deep_queries.rs`.
#[cfg(any(coverage, windows))]
const SMALL_STACK: usize = 8 << 20;

/// Parses on a [`SMALL_STACK`]: the error kinds and the depth of the tree.
fn parse_on_small_stack(name: &'static str, source: String) -> (Vec<ErrorKind>, usize) {
    let started = Instant::now();
    let out = std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(move || {
            let (root, parse) = parser::parse(&source);
            assert_eq!(root.text().to_string(), source, "{name}: lossless");
            (
                parse.errors.iter().map(|e| e.kind).collect::<Vec<_>>(),
                parse.depth,
            )
        })
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .join()
        .unwrap_or_else(|_| panic!("{name}: the parser panicked or overflowed the stack"));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{name}: took {:?}",
        started.elapsed()
    );
    out
}

/// Each recursive construct, nested `n` levels deep around `core`, as a valid query. One
/// level is one `enter`: a call, a subquery and a named subquery are a level each, so the
/// pairs (`f({ ... })`) are `n / 2` deep.
fn constructs(n: usize) -> Vec<(&'static str, String)> {
    let rep = |open: &str, core: &str, close: &str| {
        format!("{}{core}{}", open.repeat(n), close.repeat(n))
    };
    let pairs = n / 2;
    let pair = |open: &str, core: &str, close: &str| {
        format!("{}{core}{}", open.repeat(pairs), close.repeat(pairs))
    };
    vec![
        ("filter parentheses", rep("(", "a=1", ")")),
        ("not chain", format!("{}a=1", "not ".repeat(n))),
        ("bang chain", format!("{}a=1", "!".repeat(n))),
        (
            "expression parentheses",
            format!("x := {}", rep("(", "a", ")")),
        ),
        (
            "expression parentheses with operators",
            format!("x := {}", rep("(a + b * ", "c", ") - 1")),
        ),
        ("function calls", rep("f(", "a", ")")),
        ("function calls with operators", rep("f(a + ", "b", ")")),
        ("named arguments", rep("f(a=", "b", ")")),
        ("arrays", format!("x := {}", rep("[", "a", "]"))),
        // The call is a level too: `n - 1` arrays inside it.
        (
            "array elements with assignments",
            format!("f({}b{})", "[a := ".repeat(n - 1), "]".repeat(n - 1)),
        ),
        ("subqueries", rep("x := { ", "a=1", " }")),
        ("subqueries in calls", pair("f({ ", "a=1", " })")),
        ("named subqueries", pair("f(a: { ", "a=1", " })")),
        ("case statements", rep("case { ", "a=1", " }")),
        ("match statements", rep("x match { * => ", "a=1", " }")),
        ("attributes", pair("f({ f(a=1) } a: ", "b", ")")),
    ]
}

#[test]
fn every_construct_parses_at_the_nesting_floor() {
    for (name, source) in constructs(FLOOR) {
        let (errors, _) = parse_on_small_stack(name, source);
        assert!(errors.is_empty(), "{name}: {errors:?}");
    }
}

#[test]
fn past_max_depth_it_is_one_error_and_no_overflow() {
    for (name, source) in constructs(parser::MAX_DEPTH as usize * 3) {
        let (errors, _) = parse_on_small_stack(name, source);
        let too_deep: Vec<_> = errors
            .iter()
            .filter(|k| matches!(k, ErrorKind::TooDeep { .. }))
            .collect();
        assert_eq!(too_deep.len(), 1, "{name}: {errors:?}");
        // The levels run out first, except for `attributes`, which opens more than four
        // tree nodes a level and meets the toolkit's budget of nodes first (#1427).
        let budget = u32::try_from(opentide_parse::TREE_BUDGET).unwrap_or(u32::MAX);
        let limit = if name == "attributes" {
            budget
        } else {
            parser::MAX_DEPTH
        };
        assert_eq!(
            too_deep[0],
            &ErrorKind::TooDeep { limit },
            "{name}: the error names the limit that was hit"
        );
    }
    // Far past it: still one error, and no time spent on the rest.
    let (errors, _) = parse_on_small_stack(
        "filter parentheses",
        format!("{}a=1{}", "(".repeat(100_000), ")".repeat(100_000)),
    );
    assert_eq!(
        errors
            .iter()
            .filter(|k| matches!(k, ErrorKind::TooDeep { .. }))
            .count(),
        1,
        "{errors:?}"
    );
}

/// A negated call in an argument opens four tree nodes per level (a unary expression, a call,
/// an argument list, an argument): at `max_depth` the tree stays under the toolkit's
/// `MAX_TREE_DEPTH`, so `TooDeep` is the only error, never `TreeTooDeep`.
#[test]
fn max_depth_stays_under_the_tree_limit() {
    for n in [parser::MAX_DEPTH as usize, parser::MAX_DEPTH as usize + 1] {
        let source = format!("{}a{}", "f(!".repeat(n), ")".repeat(n));
        let (errors, depth) = parse_on_small_stack("negated calls", source);
        assert!(
            !errors
                .iter()
                .any(|k| matches!(k, ErrorKind::TreeTooDeep { .. })),
            "{n}: {errors:?}"
        );
        assert!(depth < opentide_parse::MAX_TREE_DEPTH, "{n}: {depth}");
    }
}

#[test]
fn the_limit_is_what_the_message_says() {
    let (_, parse) = parser::parse(&"(".repeat(2_000));
    let message = parse
        .errors
        .iter()
        .find(|e| matches!(e.kind, ErrorKind::TooDeep { .. }))
        .map(|e| e.message.clone())
        .unwrap_or_default();
    assert_eq!(message, "nesting deeper than 1000 levels");
}

#[test]
fn a_chain_of_twenty_thousand_terms_is_flat() {
    for (name, term, op) in [
        ("or", "a=1", " or "),
        ("and", "a=1", " and "),
        ("juxtaposition", "a=1", " "),
        ("pipes", "a=1", " | "),
        ("sum", "a", " + "),
        ("comparison", "a", " == "),
        ("product", "a", " * "),
    ] {
        let body = vec![term; CHAIN].join(op);
        let source = if matches!(name, "sum" | "comparison" | "product") {
            format!("x := {body}")
        } else {
            body
        };
        let (errors, depth) = parse_on_small_stack(name, source);
        assert!(errors.is_empty(), "{name}: {errors:?}");
        assert!(depth < 20, "{name}: the tree is {depth} levels deep");
    }
}

#[test]
fn long_flat_runs_of_other_shapes() {
    for (name, source) in [
        ("arguments", format!("f({})", vec!["a"; CHAIN].join(", "))),
        (
            "array elements",
            format!("f([{}])", vec!["a"; CHAIN].join(", ")),
        ),
        (
            "case branches",
            format!("case {{ {} }}", vec!["a=1"; CHAIN].join(" ; ")),
        ),
        ("assignments", vec!["x := 1"; CHAIN].join(" | ")),
        (
            "saved query arguments",
            format!("$q({})", vec!["a=b"; CHAIN].join(", ")),
        ),
    ] {
        let (errors, depth) = parse_on_small_stack(name, source);
        assert!(errors.is_empty(), "{name}: {errors:?}");
        assert!(depth < 20, "{name}: {depth}");
    }
}

/// A call in an operand of each precedence in turn is up to seven tree nodes a level, and
/// binary operators are not levels of `max_depth`: the toolkit charges each level the nodes
/// it opens, so the shape stops under 1,000 levels with one `TooDeep` naming the node budget,
/// never `TreeTooDeep`, no overflow and nothing after it. The 1,000-level floor is for
/// parenthesised nesting (`deep_queries`, ADR 0012, #1427).
#[test]
fn operator_operands_reach_the_tree_limit_as_one_error() {
    for (shape, clean_at, past) in [("f(a + !", 800, 830), ("f(a == b + c * !", 570, 600)] {
        let build = |n: usize| format!("{}a{}", shape.repeat(n), ")".repeat(n));
        let (errors, depth) = parse_on_small_stack("operands", build(clean_at));
        assert!(errors.is_empty(), "{shape} x{clean_at}: {errors:?}");
        assert!(depth < opentide_parse::MAX_TREE_DEPTH, "{shape}: {depth}");
        let (errors, depth) = parse_on_small_stack("operands", build(past));
        let budget = u32::try_from(opentide_parse::TREE_BUDGET).unwrap_or(u32::MAX);
        assert_eq!(
            errors,
            [ErrorKind::TooDeep { limit: budget }],
            "{shape} x{past}"
        );
        assert!(depth <= opentide_parse::MAX_TREE_DEPTH, "{shape}: {depth}");
    }
}
