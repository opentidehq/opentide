//! Linear on broken input (ADR 0012, decision 4): each input is analysed at `n` and at `4n`,
//! and the larger may take at most about four times as long, never sixteen. Growth is compared,
//! never an absolute time, so a slow machine does not fail it.
//!
//! The work itself is linear: under callgrind, "stray colons" takes 464.2 M instructions at
//! 20,000 and 1,844.9 M at 80,000 (3.97x), and allocates 54.0 MB in 161,387 blocks against
//! 213.3 MB in 641,403 (3.95x, 3.97x). Its wall time is not: the peak heap grows from 21 MB to
//! 81 MB (the parser's event buffer is most of it), so the larger run leaves the caches, and on a
//! shared runner the two sizes are slowed unevenly. CI saw 57 ms against 479 ms and 73 ms against
//! 682 ms. So each measurement alternates the sizes and keeps the best of three of each, and a
//! growth over the bound is measured again: the test fails only when every one of three
//! measurements shows it. Quadratic work (16x) exceeds 8x every time; a busy spell does not.

use std::time::{Duration, Instant};

use opentide_datadog::{Context, analyze_with};

const N: usize = 20_000;

/// Runs of each size per measurement, alternated, the best kept.
const RUNS: usize = 3;

/// Measurements before a growth over the bound fails the test.
const MEASUREMENTS: usize = 3;

/// A case: its name, and the input of size `n`.
type Case = (&'static str, fn(usize) -> String);

/// One analysis of `source`, timed.
fn time(source: &str) -> Duration {
    let start = Instant::now();
    std::hint::black_box(analyze_with(source, &Context::RULE));
    start.elapsed()
}

/// The best of [`RUNS`] analyses of each of `small` and `large`, alternated so that a busy
/// spell slows both sizes alike.
fn measure(small: &str, large: &str) -> (Duration, Duration) {
    let (mut best_small, mut best_large) = (Duration::MAX, Duration::MAX);
    for _ in 0..RUNS {
        best_small = best_small.min(time(small));
        best_large = best_large.min(time(large));
    }
    (best_small, best_large)
}

fn grows_linearly(name: &str, build: impl Fn(usize) -> String) {
    let (small_source, large_source) = (build(N), build(4 * N));
    let mut seen = Vec::with_capacity(MEASUREMENTS);
    for _ in 0..MEASUREMENTS {
        let (small, large) = measure(&small_source, &large_source);
        // 4x the input: linear is about 4x; quadratic would be 16x. Allow 8x, and a floor so
        // that a run too fast to time does not fail.
        let bound = small.saturating_mul(8).max(Duration::from_millis(50));
        if large <= bound {
            return;
        }
        seen.push((small, large));
    }
    panic!(
        "{name}: not linear from {N} to {} in any of {MEASUREMENTS} measurements \
         (best of {RUNS}, small and large): {seen:?}",
        4 * N
    );
}

#[test]
fn broken_inputs_are_linear() {
    let cases: [Case; 12] = [
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
    let cases: [Case; 6] = [
        // ORs nested around a long AND run: each level's message must not re-read the run.
        ("nested ORs", |n| {
            let mut s = "a ".repeat(n);
            for _ in 0..n / 100 {
                s = format!("({s} x OR y)");
            }
            s
        }),
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
