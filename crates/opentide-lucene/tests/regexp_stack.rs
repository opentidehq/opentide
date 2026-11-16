//! Lucene regexp bodies on a 1 MB stack (the browser module's): every shape
//! that nests or chains, at the depth limit and past it, and a million
//! characters of each, through `regexp::elasticsearch_problems` and the
//! Lucene query's `/…/` term. EQL `regex` and ES|QL `RLIKE`, which check the
//! same bodies, have their own copies of these tests. Found by review: the
//! checker recursed once per group, `~`, repetition and `&`, built and
//! dropped a tree as deep, and aborted on a few hundred levels.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::Severity;
use opentide_lucene::regexp::{MAX_DEPTH, elasticsearch_problems};
use std::time::{Duration, Instant};

/// The stack the checks run on: the browser WASM module's 1 MB; 8 MB on
/// Windows and under coverage, whose frames are larger (the rule of
/// `crates/opentide-analysis/tests/deep_queries.rs`).
#[cfg(not(any(coverage, windows)))]
const SMALL_STACK: usize = 1 << 20;
/// See above.
#[cfg(any(coverage, windows))]
const SMALL_STACK: usize = 8 << 20;

/// Runs `run` on a [`SMALL_STACK`] thread within 60 s; an overflow aborts.
fn on_small_stack<T: Send + 'static>(name: &str, run: impl FnOnce() -> T + Send + 'static) -> T {
    let started = Instant::now();
    let out = std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(run)
        .expect("spawn")
        .join()
        .expect("the check overflowed or panicked");
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{name}: {:?}",
        started.elapsed()
    );
    out
}

/// The shapes that nest or chain, each a body: (name, body, too deep).
fn shapes(n: usize) -> Vec<(String, String, bool)> {
    vec![
        // Past the limit the parser stops at the `(` that goes too deep,
        // before it could see that the groups are never closed.
        (format!("{n} open groups"), "(".repeat(n), n > MAX_DEPTH),
        (
            format!("{n} groups"),
            format!("{}a{}", "(".repeat(n), ")".repeat(n)),
            n > MAX_DEPTH,
        ),
        (format!("{n} `&`"), "a&".repeat(n) + "a", n >= MAX_DEPTH),
        (format!("{n} `~`"), "~".repeat(n) + "a", n >= MAX_DEPTH),
        (
            format!("{n} `*`"),
            "a".to_string() + &"*".repeat(n),
            n >= MAX_DEPTH,
        ),
        (format!("{n} `|`"), "a|".repeat(n) + "b", false),
        (format!("{n} `ab.`"), "ab.".repeat(n), false),
        (format!("{n} `a`"), "a".repeat(n), false),
    ]
}

#[test]
fn the_shapes_at_and_past_the_limit_return() {
    for n in [MAX_DEPTH - 1, MAX_DEPTH, MAX_DEPTH + 1, 400, 1_600] {
        for (name, body, too_deep) in shapes(n) {
            let problems = on_small_stack(&name, move || elasticsearch_problems(&body));
            let deep = problems
                .iter()
                .any(|p| p.message.contains("does not check it"));
            assert_eq!(deep, too_deep, "{name}: {problems:?}");
            if deep {
                // One finding, a warning: Lucene has no limit of its own.
                assert_eq!(problems.len(), 1, "{name}: {problems:?}");
                assert_eq!(problems[0].severity, Severity::Warning, "{name}");
            }
        }
    }
}

#[test]
fn a_million_characters_of_each_shape() {
    for (name, body, _) in shapes(1_000_000 / 3) {
        let _ = on_small_stack(&name, move || elasticsearch_problems(&body));
    }
}

/// The query's `/…/` term reaches the same checker.
#[test]
fn through_a_lucene_query() {
    for (name, body, _) in shapes(400).into_iter().chain(shapes(100_000)) {
        let query = format!("a:/{body}/");
        let _ = on_small_stack(&name, move || opentide_lucene::analyze(&query).diagnostics);
    }
}
