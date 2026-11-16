//! Deeply nested subsearches on the 1 MB stack of the browser module. The
//! checks that walk subsearches (data models, declared datasets, the
//! performance lints, the search operators) recursed once per `[` and aborted
//! the process at 1,000 levels, after the parser had already reported the
//! query; each also rescanned every level. They walk on a stack of their own
//! now, to the depth the parser accepts.

use std::thread;
use std::time::{Duration, Instant};

/// `analyze`, completions and hover at the end of `source`, on a 1 MB stack;
/// `false` when the thread overflowed or panicked.
fn survives(source: String) -> bool {
    thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            opentide_spl::analyze(&source);
            opentide_spl::completions(&source, source.len());
            opentide_spl::hover(&source, source.len() / 2);
        })
        .map(|h| h.join().is_ok())
        .unwrap_or(false)
}

/// Every shape a walker descends: plain subsearches (search operators),
/// `join` (the truncation lint), `tstats` over data models (CIM and the
/// declared datasets) and `search` clauses with operators.
fn shapes(n: usize) -> Vec<String> {
    let nest = |open: &str, inner: &str| format!("{}{inner}{}", open.repeat(n), "]".repeat(n));
    vec![
        format!("index=x {}", nest("[", "a")),
        format!(
            "index=x | join a {}",
            nest("[search index=y | join a ", "b")
        ),
        format!(
            "| tstats count from datamodel=Network_Traffic where {}",
            nest(
                "[| tstats count from datamodel=Authentication.Authentication where ",
                "Authentication.user=a"
            )
        ),
        format!("index=x a == b {}", nest("[search a == b NOT ", "c")),
        // Unclosed: the walk ends at the end of the text.
        format!("index=x {}a", "[search ".repeat(n)),
    ]
}

#[test]
fn a_thousand_nested_subsearches_do_not_overflow() {
    for source in shapes(1_000) {
        let head: String = source.chars().take(60).collect();
        assert!(survives(source), "overflowed or panicked on `{head}…`");
    }
}

#[test]
fn a_hundred_thousand_nested_subsearches_do_not_overflow() {
    for source in shapes(100_000) {
        let head: String = source.chars().take(60).collect();
        let started = Instant::now();
        assert!(survives(source), "overflowed or panicked on `{head}…`");
        // The walks stop at the parser's depth: bounded work, far under this.
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "`{head}…` took {:?}",
            started.elapsed()
        );
    }
}
