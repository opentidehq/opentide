//! Linear on broken input (ADR 0012, decision 4): each input is analysed at `n` and at `4n`,
//! and the larger may take at most about four times as long, never sixteen. Growth is compared,
//! never an absolute time, so a slow machine does not fail it.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use std::time::{Duration, Instant};

use opentide_datadog::{Context, analyze_with};

const N: usize = 20_000;

/// The best of three runs of the analysis of `source`.
fn time(source: &str) -> Duration {
    (0..3)
        .map(|_| {
            let start = Instant::now();
            std::hint::black_box(analyze_with(source, &Context::RULE));
            start.elapsed()
        })
        .min()
        .expect("three runs")
}

fn grows_linearly(name: &str, build: impl Fn(usize) -> String) {
    let small = time(&build(N));
    let large = time(&build(4 * N));
    // 4x the input: linear is about 4x; quadratic would be 16x. Allow 8x, and a floor so
    // that a run too fast to time does not fail.
    let bound = small.saturating_mul(8).max(Duration::from_millis(50));
    assert!(
        large <= bound,
        "{name}: {small:?} at {N}, {large:?} at {}: not linear",
        4 * N
    );
}

#[test]
fn broken_inputs_are_linear() {
    let cases: [(&str, fn(usize) -> String); 12] = [
        ("unclosed quotes", |n| "\"a ".repeat(n)),
        ("escaped quotes", |n| format!("\"{}", "\\\"".repeat(n))),
        ("stray closers", |n| "a ) ".repeat(n)),
        ("stray colons", |n| ": ".repeat(n)),
        ("open groups", |n| "(a ".repeat(n)),
        ("fields with no value", |n| "@a: ".repeat(n)),
        ("unclosed ranges", |n| "@a:[1 TO ".repeat(n)),
        ("ranges without TO", |n| "@a:[1 2] ".repeat(n)),
        ("dangling operators", |n| "a OR AND ".repeat(n)),
        ("stacked modifiers", |n| "--a ".repeat(n)),
        ("broken CIDR calls", |n| "CIDR(@ip, ".repeat(n)),
        ("unescaped specials", |n| "a!b~c ".repeat(n)),
    ];
    for (name, build) in cases {
        grows_linearly(name, build);
    }
}

#[test]
fn long_valid_inputs_are_linear() {
    let cases: [(&str, fn(usize) -> String); 5] = [
        ("an AND chain", |n| "@a:b ".repeat(n)),
        ("an OR chain", |n| vec!["@a:b"; n].join(" OR ")),
        ("a mixed chain", |n| "a b OR ".repeat(n) + "c"),
        ("a value group", |n| {
            format!("@a:({})", vec!["x"; n].join(" OR "))
        }),
        ("lower-case operators", |n| {
            format!("@a:({})", vec!["x"; n].join(" or "))
        }),
    ];
    for (name, build) in cases {
        grows_linearly(name, build);
    }
}
