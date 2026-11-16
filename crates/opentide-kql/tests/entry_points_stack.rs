//! Every analysis entry point on a 1 MB stack (the browser's), over the
//! lexer's long tokens at a million repeats and over the deepest input the
//! parser accepts (#1230): an abort or a quadratic walk fails here. The
//! analysis walks the tree with loops; a recursion per tree level (rowan's
//! `token_at_offset` is one) would overflow on the 20,000-term chain.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_kql::{
    Catalog, Profile, analyze_with_catalog, columns, completions, hover, lower, signature_help,
};
use std::time::{Duration, Instant};

/// Runs every entry point on `source` on a 1 MB stack and returns how long
/// they took and the codes of the diagnostics.
fn every_entry_point(source: String) -> (Duration, Vec<String>) {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let started = Instant::now();
            let catalog = Catalog::for_workspace(Profile::Sentinel, &source);
            let analysis = analyze_with_catalog(&source, &catalog);
            let _ = columns(&source, Profile::Defender);
            let _ = lower(&source);
            for offset in [0, source.len() / 2, source.len()] {
                let _ = hover(&source, offset, Profile::Sentinel);
                let _ = completions(&source, offset, Profile::Sentinel);
                let _ = signature_help(&source, offset, Profile::Sentinel);
            }
            let codes = analysis.diagnostics.into_iter().map(|d| d.code).collect();
            (started.elapsed(), codes)
        })
        .expect("spawn")
        .join()
        .expect("an entry point panicked")
}

const N: usize = 1_000_000;

fn assert_fast(name: &str, elapsed: Duration) {
    assert!(elapsed < Duration::from_secs(60), "{name}: {elapsed:?}");
}

#[test]
fn long_tokens_in_a_query() {
    let cases: Vec<(&str, String)> = vec![
        ("string", format!("\"{}\"", "a".repeat(N))),
        ("escapes", format!("'{}'", "\\'".repeat(N))),
        ("verbatim", format!("@\"{}\"", "\"\"".repeat(N))),
        ("fence", format!("```{}```", "`a".repeat(N))),
        ("quoted name", format!("['{}']", "a".repeat(N))),
        ("number", "1".repeat(N)),
        ("timespan", format!("{}m", "1".repeat(N))),
        ("typed literal", format!("datetime({})", "1".repeat(N))),
        ("comment", format!("//{}", "a".repeat(N))),
        ("white space", " ".repeat(N)),
        ("unclosed string", format!("\"{}", "a".repeat(N))),
    ];
    for (name, token) in cases {
        let source = format!("SecurityEvent | where Account == {token} | take 1");
        let (elapsed, _) = every_entry_point(source);
        assert_fast(name, elapsed);
    }
    // Many short tokens of each class.
    for (name, token) in [
        ("names", "a "),
        ("pipes", "| take 1 "),
        ("strings", "\"x\" "),
        ("quoted names", "['x'] "),
        ("commas", ", "),
    ] {
        let source = format!("SecurityEvent | project {}", token.repeat(N / 10));
        let (elapsed, _) = every_entry_point(source);
        assert_fast(name, elapsed);
    }
}

#[test]
fn deep_input() {
    let chain = vec!["a == 1"; 20_000].join(" or ");
    let cases = [
        ("chain", format!("T | where {chain}"), false),
        ("broken chain", format!("T | where {chain} or"), true),
        (
            "nesting",
            format!("T | where {}a == 1{}", "(".repeat(254), ")".repeat(254)),
            false,
        ),
        (
            "too deep",
            format!("T | where {}a == 1{}", "(".repeat(5_000), ")".repeat(5_000)),
            true,
        ),
        (
            "unclosed",
            format!("T | where {}a == 1", "(".repeat(5_000)),
            true,
        ),
        ("pipes", format!("T{}", " | take 1".repeat(20_000)), false),
    ];
    for (name, source, broken) in cases {
        let (elapsed, codes) = every_entry_point(source);
        assert_fast(name, elapsed);
        assert_eq!(
            codes.iter().any(|c| c == "kql_parse_error"),
            broken,
            "{name}: {codes:?}"
        );
    }
}
