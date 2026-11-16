//! Every recursive construct at the nesting floor and far past `max_depth`,
//! on a 1 MB stack (the browser module's): one diagnostic past the limit, and
//! no stack overflow while parsing, walking or dropping the tree.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_parse::ErrorKind;
use opentide_spl::syntax::{MAX_DEPTH, parse};

fn on_small_stack(source: String) -> (usize, bool) {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let (tree, parsed) = parse(&source);
            assert_eq!(tree.to_string(), source, "lossless");
            let too_deep = parsed
                .errors
                .iter()
                .any(|e| matches!(e.kind, ErrorKind::TooDeep { .. }));
            (parsed.errors.len(), too_deep)
        })
        .expect("spawn")
        .join()
        .expect("no overflow")
}

fn constructs(n: usize) -> Vec<(&'static str, String)> {
    let nested = |open: &str, close: &str, core: &str| {
        format!("{}{core}{}", open.repeat(n), close.repeat(n))
    };
    vec![
        ("groups", nested("(", ")", "a")),
        ("groups after a field", nested("a=1 (", ")", "b")),
        ("subsearches", nested("[ search ", " ]", "a")),
        ("bare subsearches", nested("[ ", " ]", "a")),
        ("search subsearches", nested("a [ search b ", " ]", "c")),
        ("piped subsearches", nested("a [ | ", " ]", "head 1")),
        ("subsearch in a where", nested("| where x=[ ", " ]", "a")),
        ("eval parens", format!("| eval x={}", nested("(", ")", "1"))),
        ("eval calls", format!("| eval x={}", nested("f(", ")", "1"))),
        ("where parens", format!("| where {}", nested("(", ")", "x"))),
        (
            "stats calls",
            format!("| stats {}", nested("eval(", ")", "x")),
        ),
        (
            "tstats calls",
            format!("| tstats {}", nested("f(", ")", "x")),
        ),
        (
            "option calls",
            format!("| foo a={}", nested("f(", ")", "1")),
        ),
        ("unknown calls", format!("| foo {}", nested("f(", ")", "1"))),
        ("sort calls", format!("| sort {}", nested("f(", ")", "x"))),
        (
            "rename calls",
            format!("| rename {} as x", nested("f(", ")", "y")),
        ),
        (
            "tojson calls",
            format!("| tojson {}", nested("f(", ")", "x")),
        ),
        ("foreach bodies", nested("| foreach * [ ", " ]", "eval x=1")),
        ("join bodies", nested("| join a [ ", " ]", "search b")),
        ("not chain", format!("{}a", "NOT ".repeat(n))),
        ("unary chain", format!("| eval x={}1", "-".repeat(n))),
        ("or chain", format!("| where {}a", "a or ".repeat(n))),
        ("pipes", format!("a{}", " | head 1".repeat(n))),
        ("macros", "`m` ".repeat(n)),
    ]
}

/// The constructs that nest through a subsearch cost four levels each.
const SUBSEARCH_FAMILY: [&str; 7] = [
    "subsearches",
    "bare subsearches",
    "search subsearches",
    "piped subsearches",
    "subsearch in a where",
    "foreach bodies",
    "join bodies",
];

#[test]
fn nesting_at_the_floor_parses_on_a_small_stack() {
    let floor = MAX_DEPTH as usize;
    // Groups, parentheses and calls reach the floor itself (one level less
    // than the limit, for the root); a subsearch costs four levels.
    for n in [floor / 2, floor - 2] {
        for (name, source) in constructs(n) {
            if SUBSEARCH_FAMILY.contains(&name) {
                continue;
            }
            let (errors, too_deep) = on_small_stack(source);
            assert!(!too_deep, "{name} x {n}: too deep ({errors} errors)");
        }
    }
    for (name, source) in constructs(floor / 4 - 1) {
        if SUBSEARCH_FAMILY.contains(&name) {
            let (errors, too_deep) = on_small_stack(source);
            assert!(
                !too_deep,
                "{name}: too deep at a quarter of the limit ({errors} errors)"
            );
        }
    }
}

#[test]
fn nesting_past_the_limit_is_one_diagnostic_on_a_small_stack() {
    for n in [MAX_DEPTH as usize + 2, 20_000, 200_000] {
        for (name, source) in constructs(n) {
            eprintln!("{name} x {n}");
            let (errors, too_deep) = on_small_stack(source);
            // Flat chains have no limit; only nesting reports it.
            let flat = matches!(
                name,
                "not chain" | "unary chain" | "or chain" | "pipes" | "macros"
            );
            if !flat {
                assert!(too_deep, "{name} x {n}: no TooDeep ({errors} errors)");
            }
        }
    }
}
