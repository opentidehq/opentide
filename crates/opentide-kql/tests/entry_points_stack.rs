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
    // Many short tokens of each class, in a valid query, so that every pass
    // reads them all (a broken one stops at its error).
    // A call costs a catalog lookup (about 0.5 ms in a debug build, linear:
    // 12,500 took 6 s, 25,000 took 12 s), so calls run at a quarter of that.
    for (name, item, count) in [
        ("names", "a", N / 10),
        ("strings", "\"x\"", N / 10),
        ("quoted names", "['x']", N / 10),
        ("numbers", "1", N / 10),
        ("timespans", "5m", N / 10),
        ("calls", "strlen(a)", N / 40),
    ] {
        let source = format!(
            "SecurityEvent | where a in ({})",
            vec![item; count].join(", ")
        );
        let (elapsed, codes) = every_entry_point(source);
        assert_fast(name, elapsed);
        assert!(
            !codes.iter().any(|c| c == "kql_parse_error"),
            "{name}: {codes:?}"
        );
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

/// Found on CI (#1411): a quoted name of a million characters that is no
/// column of a documented table was measured (Levenshtein) against every
/// column, 9 s per analysis in a debug build; a candidate whose length is too
/// far off is no longer measured.
#[test]
fn a_long_unknown_column_is_not_measured_against_every_column() {
    let source = format!(
        "SecurityEvent | where Account == ['{}'] | take 1",
        "a".repeat(N)
    );
    let catalog = Catalog::for_workspace(Profile::Sentinel, &source);
    let before = opentide_kql::inspect::columns_measured();
    let started = Instant::now();
    let _ = analyze_with_catalog(&source, &catalog);
    let _ = hover(&source, 0, Profile::Sentinel);
    // A hang guard, as for the other entry points here; the count below is
    // the regression test.
    assert_fast("a long unknown column", started.elapsed());
    assert_eq!(
        opentide_kql::inspect::columns_measured(),
        before,
        "a name of a million characters was measured against a column"
    );
    // A near miss still is.
    let before = opentide_kql::inspect::columns_measured();
    let near = analyze_with_catalog(
        "SecurityEvent | where Acount == 'x' | take 1",
        &Catalog::for_workspace(Profile::Sentinel, ""),
    );
    assert!(opentide_kql::inspect::columns_measured() > before);
    assert!(
        near.diagnostics
            .iter()
            .any(|d| d.suggestion.as_deref() == Some("Account")),
        "{:?}",
        near.diagnostics
    );
}

/// #1424: each call to a `let` function re-read its body, so a chain of
/// functions that call the one before was quadratic, and exponential when
/// each calls it twice (a 600-byte query of 16 functions took seconds, 30
/// would take hours). Each body is now read once, where it is defined; the
/// unit test `each_function_body_is_read_once` holds the count, this one
/// runs every entry point over both shapes.
#[test]
fn chains_of_functions_are_read_once() {
    let chain = |n: usize, calls: usize| {
        let mut out = String::from("let f0 = () { SigninLogs | project UserPrincipalName };\n");
        for i in 1..n {
            let call = format!("f{}()", i - 1);
            let body = vec![call; calls].join(", ");
            let body = if calls == 1 {
                body
            } else {
                format!("union {body}")
            };
            out.push_str(&format!("let f{i} = () {{ {body} }};\n"));
        }
        out.push_str(&format!("f{}() | where Nope == 1", n - 1));
        out
    };
    for (name, source) in [
        ("4,000 functions in a chain", chain(4_000, 1)),
        ("40 functions calling the one before twice", chain(40, 2)),
    ] {
        let (elapsed, codes) = every_entry_point(source);
        assert_fast(name, elapsed);
        assert!(
            codes.iter().any(|c| c == "kql_unknown_column"),
            "{name}: {codes:?}"
        );
    }
}
