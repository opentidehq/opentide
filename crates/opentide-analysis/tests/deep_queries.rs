//! Deeply nested queries must not overflow the stack or go quadratic. A long
//! `OR` chain parses as a tree thousands of levels deep; the browser WASM
//! module runs with a 1 MB stack, so every engine is checked on one here,
//! within a time budget that a quadratic walk (`Node::parent` re-descends
//! from the root on every call) would blow.

use std::thread;
use std::time::{Duration, Instant};

fn on_small_stack(name: &str, run: impl FnOnce() + Send + 'static) {
    let started = Instant::now();
    thread::Builder::new()
        .name(name.into())
        .stack_size(1 << 20)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap_or_else(|_| panic!("{name} overflowed or panicked"));
    // Linear engines take about a second here in a debug build.
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{name} took {:?}",
        started.elapsed()
    );
}

fn chain(term: &str, op: &str, n: usize) -> String {
    vec![term; n].join(op)
}

#[test]
fn long_or_chains_do_not_overflow_the_stack() {
    const N: usize = 20_000;
    on_small_stack("esql", || {
        let q = format!("FROM logs-* | WHERE {}", chain("a == 1", " OR ", N));
        opentide_esql::analyze(&q);
    });
    on_small_stack("eql", || {
        let q = format!("process where {}", chain("a == 1", " or ", N));
        opentide_eql::analyze(&q);
    });
    on_small_stack("kuery", || {
        opentide_kuery::analyze(&chain("a:1", " or ", N));
    });
    on_small_stack("lucene", || {
        opentide_lucene::analyze(&chain("a:1", " OR ", N));
    });
}
