//! EQL `regex` bodies of the Lucene regexp checker on a 1 MB stack (the browser
//! module's): every shape that nests or chains, at the depth limit and past
//! it, and a million characters of each, through `opentide_eql::analyze`.
//! The same shapes as `crates/opentide-lucene/tests/regexp_stack.rs`. Found
//! by review: the checker recursed once per group, `~`, repetition and `&`,
//! and aborted on a few hundred levels.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::Severity;
use opentide_lucene::regexp::MAX_DEPTH;
use std::time::{Duration, Instant};

/// The stack the checks run on: the browser WASM module's 1 MB; 8 MB on
/// Windows and under coverage, whose frames are larger (the rule of
/// `crates/opentide-analysis/tests/deep_queries.rs`).
#[cfg(not(any(coverage, windows)))]
const SMALL_STACK: usize = 1 << 20;
/// See above.
#[cfg(any(coverage, windows))]
const SMALL_STACK: usize = 8 << 20;

/// The query around a regexp body.
fn query(body: &str) -> String {
    format!(r#"process where process.name regex "{body}""#)
}

/// Analyzes the query around `body` on a [`SMALL_STACK`] thread within
/// 60 s: the regexp checker's findings, (severity, message).
fn findings(name: &str, body: &str) -> Vec<(Severity, String)> {
    let source = query(body);
    let started = Instant::now();
    let out = std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(move || {
            opentide_eql::analyze(&source)
                .diagnostics
                .into_iter()
                .map(|d| (d.severity, d.message))
                .collect()
        })
        .expect("spawn")
        .join()
        .expect("the analysis overflowed or panicked");
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
            let found = findings(&name, &body);
            let deep: Vec<_> = found
                .iter()
                .filter(|(_, m)| m.contains("does not check it"))
                .collect();
            assert_eq!(!deep.is_empty(), too_deep, "{name}: {found:?}");
            if too_deep {
                // One finding, a warning: Lucene has no limit of its own.
                assert_eq!(deep.len(), 1, "{name}: {found:?}");
                assert_eq!(deep[0].0, Severity::Warning, "{name}");
            }
        }
    }
}

#[test]
fn a_million_characters_of_each_shape() {
    for (name, body, _) in shapes(1_000_000 / 3) {
        let _ = findings(&name, &body);
    }
}
