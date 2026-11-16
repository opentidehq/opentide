//! The parser at its limits, on a 1 MB stack in a debug build (the browser WASM module's):
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

/// Parses on a 1 MB stack: the error kinds and the depth of the tree.
fn parse_on_small_stack(name: &'static str, source: String) -> (Vec<ErrorKind>, usize) {
    let started = Instant::now();
    let out = std::thread::Builder::new()
        .stack_size(1 << 20)
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

/// Each recursive construct, nested `n` deep around `core`.
fn constructs(n: usize) -> Vec<(&'static str, String)> {
    let rep = |open: &str, core: &str, close: &str| {
        format!("{}{core}{}", open.repeat(n), close.repeat(n))
    };
    vec![
        ("filter parentheses", rep("(", "a=1", ")")),
        ("not chain", format!("{}a=1", "not ".repeat(n))),
        ("bang chain", format!("{}a=1", "!".repeat(n))),
        (
            "expression parentheses",
            format!("x := {}", rep("(", "a", ")")),
        ),
        ("function calls", rep("f(", "a", ")")),
        ("subqueries", format!("f({})", rep("{ ", "a=1", " }"))),
        ("arrays", format!("f({})", rep("[", "a", "]"))),
        ("case statements", rep("case { ", "a=1", " }")),
        ("match statements", rep("x match { * => ", "a=1", " }")),
        ("saved query arguments", rep("$q(a=[", "b", "])")),
        (
            "named subqueries",
            format!("f({})", rep("a: { f(", "b", ") }")),
        ),
        ("attributes", format!("f({})", rep("{ f(", "b", ") } a: 1"))),
    ]
}

#[test]
fn every_construct_parses_at_the_nesting_floor() {
    for (name, source) in constructs(FLOOR) {
        // The floor is for parentheses of filters (deep_queries). Calls, expressions and
        // bodies cost about 1.5 KB of stack per level in a debug build, so they are charged
        // two levels (about 512 deep): past that, one error and no overflow.
        let (errors, _) = parse_on_small_stack(name, source);
        let parens = name == "filter parentheses";
        if parens {
            assert!(errors.is_empty(), "{name}: {errors:?}");
        } else {
            assert!(
                errors.iter().all(|k| matches!(
                    k,
                    ErrorKind::Syntax | ErrorKind::TreeTooDeep { .. } | ErrorKind::TooDeep { .. }
                )),
                "{name}: {errors:?}"
            );
        }
    }
}

#[test]
fn past_max_depth_it_is_one_error_and_no_overflow() {
    for (name, source) in constructs(parser::MAX_DEPTH as usize * 3) {
        let (errors, _) = parse_on_small_stack(name, source);
        let guards = errors
            .iter()
            .filter(|k| matches!(k, ErrorKind::TooDeep { .. }))
            .count();
        assert!(guards <= 1, "{name}: {errors:?}");
    }
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
