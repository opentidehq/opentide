//! Deeply nested queries must not overflow the stack or go quadratic. A long
//! `OR` chain parses as a tree thousands of levels deep; the browser WASM
//! module runs with a 1 MB stack, so every engine is checked on one here,
//! within a time budget that a quadratic walk (`Node::parent` re-descends
//! from the root on every call) would blow.
//!
//! Every language has two floors, measured on the tree-sitter engines on a
//! 1 MB stack in a debug build (`cargo test`), with bounded probes, one
//! process per size, bisecting up to a cap of 20,000 terms for chains and
//! 10,000 levels for nesting:
//!
//! - the chain floor: the longest flat `a or b or ...` chain analysed without
//!   a stack overflow, within the time budget below, and with no
//!   `<lang>_parse_error` diagnostic;
//! - the nesting floor: the deepest parenthesised nesting analysed the same way.
//!
//! A replacement parser must keep every floor (its `max_depth` sits at or
//! above it). A floor equal to the cap means the engine passed at the cap, so
//! the true limit is higher. No floor sits below its measured edge any more:
//! kql and yaral were quadratic on tree-sitter (yaral in the nesting depth
//! too), and both were measured again on their pure-Rust parsers (#1230,
//! #1227).

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use std::thread;
use std::time::{Duration, Instant};

use opentide_core::Diagnostic;

/// Cap of the chain search: the longest chain probed.
const CHAIN_CAP: usize = 20_000;
// The nesting search was capped at 10,000 levels.

// Chain floors. Measured edge (the largest size that finished within 60 s, or
// the cap), in a debug build under a host load average of 15 to 25.
/// kql: on tree-sitter, 2,000 terms took 21 s (quadratic: each highlighted name
/// rescanned the query for its tables); on the pure-Rust parser (#1230), which
/// scans once, the cap passed in 8 s.
const KQL_CHAIN_FLOOR: usize = CHAIN_CAP;
/// yaral passed the cap on the pure-Rust parser (#1227). On tree-sitter 1,000
/// terms took 6 s and 2,500 took 87 s (quadratic), so the floor was 1,000.
const YARAL_CHAIN_FLOOR: usize = CHAIN_CAP;
/// spl passed the cap in 0.9 s.
const SPL_CHAIN_FLOOR: usize = CHAIN_CAP;
/// cql passed the cap in 0.3 s.
const CQL_CHAIN_FLOOR: usize = CHAIN_CAP;
/// yara passed the cap in 0.2 s.
const YARA_CHAIN_FLOOR: usize = CHAIN_CAP;
/// exabeam passed the cap in 0.3 s.
const EXABEAM_CHAIN_FLOOR: usize = CHAIN_CAP;
/// falco passed the cap in 8 s.
const FALCO_CHAIN_FLOOR: usize = CHAIN_CAP;
/// esql passed the cap in 0.4 s.
const ESQL_CHAIN_FLOOR: usize = CHAIN_CAP;
/// eql passed the cap in 0.3 s.
const EQL_CHAIN_FLOOR: usize = CHAIN_CAP;
/// kuery passed the cap in 0.4 s.
const KUERY_CHAIN_FLOOR: usize = CHAIN_CAP;
/// lucene passed the cap in 0.3 s.
const LUCENE_CHAIN_FLOOR: usize = CHAIN_CAP;
/// datadog: a new pure-Rust parser (rfc-datadog-cloud-siem), held at the cap.
const DATADOG_CHAIN_FLOOR: usize = CHAIN_CAP;

// Nesting floors: the largest depth with no stack overflow and no parse error,
// capped at NESTING_CEILING.
/// The deepest nesting every new parser must accept (epic #1219): its recursive
/// descent and the rowan tree it builds (dropped recursively) must fit the browser
/// WASM module's 1 MB stack, which cannot hold the 10,000 levels tree-sitter accepts
/// for some languages (a minimal descent on the toolkit overflows near 6,000 in a
/// debug build). 1,000 is above every vendor's own limit known (ES|QL 400, EQL 250,
/// Falco 100); past it a new parser reports one `TooDeep` diagnostic.
const NESTING_CEILING: usize = 1_000;
/// kql: tree-sitter passed 35 levels and overflowed the 1 MB stack at 36 (abort).
/// The pure-Rust parser (#1230) passes 254 and reports the nesting past its
/// `MAX_DEPTH` (256 levels; `T | where` takes two) as one error; with a higher
/// limit, a debug build overflowed 1 MB between 500 and 700 levels.
const KQL_NEST_FLOOR: usize = 254;
/// spl passed the 10,000 cap in 0.2 s; held at the ceiling.
const SPL_NEST_FLOOR: usize = NESTING_CEILING;
/// cql passed the 10,000 cap in 0.1 s; held at the ceiling.
const CQL_NEST_FLOOR: usize = NESTING_CEILING;
/// yaral passed the 10,000 cap on tree-sitter in 19 s (quadratic); held at the
/// ceiling. The pure-Rust parser (#1227) takes 1,100 levels and reports
/// "nesting deeper than 1100 levels" past them.
const YARAL_NEST_FLOOR: usize = NESTING_CEILING;
/// yara: 495 levels passed; 496 gives `yara_parse_error`.
const YARA_NEST_FLOOR: usize = 495;
/// exabeam: 199 levels passed; 200 gives `exabeam_parse_error`.
const EXABEAM_NEST_FLOOR: usize = 199;
/// falco: 18 levels passed; 19 gives `falco_parse_error`.
const FALCO_NEST_FLOOR: usize = 18;
/// esql passed the 10,000 cap in 0.1 s (it reports `esql_expression_depth`, not a
/// parse error); held at the ceiling.
const ESQL_NEST_FLOOR: usize = NESTING_CEILING;
/// eql passed the 10,000 cap in 0.1 s (it reports `eql_expression_depth`, not a
/// parse error); held at the ceiling.
const EQL_NEST_FLOOR: usize = NESTING_CEILING;
/// kuery passed the 10,000 cap in 0.04 s; held at the ceiling.
const KUERY_NEST_FLOOR: usize = NESTING_CEILING;
/// lucene passed the 10,000 cap in 0.04 s; held at the ceiling.
const LUCENE_NEST_FLOOR: usize = NESTING_CEILING;
/// datadog: a new language keeps the ceiling (`opentide-datadog` `MAX_DEPTH`, 1,000).
const DATADOG_NEST_FLOOR: usize = NESTING_CEILING;

/// The stack the floors are measured against: the browser WASM module's 1 MB.
#[cfg(not(any(coverage, windows)))]
const SMALL_STACK: usize = 1 << 20;
/// Under `cargo llvm-cov` (`--cfg coverage`) the instrumentation enlarges every frame,
/// so the depths measured on an ordinary debug build overflow 1 MB (`kql nest` aborted
/// the nightly Coverage job). A Windows debug build's frames are larger too (`kql nest`
/// aborted the nightly's Windows engine tests: the floors sit at the edge measured on
/// Linux and macOS). Neither binary is the WASM budget; the 1 MB model stays enforced
/// by the Linux and macOS test jobs. 8 MB is a generous bound, not a measurement.
#[cfg(any(coverage, windows))]
const SMALL_STACK: usize = 8 << 20;

/// The stack KQL's floors run on: [`SMALL_STACK`] less 16 KiB. glibc carves a
/// thread's static TLS out of its stack, so a test at the very edge of 1 MB
/// passed or aborted with the thread-locals the binary happened to link (the
/// tree-sitter KQL engine needed about 1,049,344 bytes for 35 levels, and an
/// 80-byte thread-local elsewhere aborted it on CI). The pure-Rust engine
/// (#1230) needs about 80 KB for 35 levels and 404 KB for 254 in a debug build.
const KQL_STACK: usize = SMALL_STACK - (16 << 10);

/// Run `run` on a [`SMALL_STACK`] and fail on an overflow, a panic or a blown time budget.
fn on_small_stack<T: Send + 'static>(name: &str, run: impl FnOnce() -> T + Send + 'static) -> T {
    on_stack(name, SMALL_STACK, run)
}

/// [`on_small_stack`] on a stack of `size` bytes.
fn on_stack<T: Send + 'static>(
    name: &str,
    size: usize,
    run: impl FnOnce() -> T + Send + 'static,
) -> T {
    let started = Instant::now();
    let out = thread::Builder::new()
        .name(name.into())
        .stack_size(size)
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
    out
}

/// The depth checks that fire on deep valid queries today: Elasticsearch caps ES|QL
/// expressions at 400 (300 on recent patches) and EQL at 250 levels, and the engines
/// say so. They are analysis findings about the vendor, not a failure to parse.
const VENDOR_DEPTH_CODES: [&str; 2] = ["esql_expression_depth", "eql_expression_depth"];

/// Like [`on_small_stack`] for a query whose diagnostics must hold no parse error and
/// no depth limit of the engine itself (a new parser's `max_depth` diagnostic must not
/// pass this gate silently); only the vendor's depth checks are tolerated.
fn analyzes_cleanly(name: &str, query: String, analyze: fn(&str) -> Vec<Diagnostic>) {
    analyzes_cleanly_on(name, SMALL_STACK, query, analyze);
}

/// [`analyzes_cleanly`] on a stack of `size` bytes.
fn analyzes_cleanly_on(
    name: &str,
    size: usize,
    query: String,
    analyze: fn(&str) -> Vec<Diagnostic>,
) {
    let diagnostics = on_stack(name, size, move || analyze(&query));
    let failures = stopped(&diagnostics);
    assert!(failures.is_empty(), "{name}: {failures:?}");
}

fn chain(term: &str, op: &str, n: usize) -> String {
    vec![term; n].join(op)
}

fn nest(atom: &str, n: usize) -> String {
    format!("{}{atom}{}", "(".repeat(n), ")".repeat(n))
}

fn kql(expr: &str) -> String {
    format!("T | where {expr}")
}

fn kql_diagnostics(q: &str) -> Vec<Diagnostic> {
    opentide_kql::analyze(q, opentide_kql::Profile::Sentinel).diagnostics
}

fn spl(expr: &str) -> String {
    format!("index=x ({expr})")
}

fn yaral(expr: &str) -> String {
    format!(
        "rule r {{\n  meta:\n    author = \"x\"\n  events:\n    {expr}\n  condition:\n    $e\n}}\n"
    )
}

const YARAL_TERM: &str = "$e.principal.hostname = \"x\"";

fn yara(expr: &str) -> String {
    format!("rule r {{\n  strings:\n    $a = \"x\"\n  condition:\n    {expr}\n}}\n")
}

fn esql(expr: &str) -> String {
    // `FROM logs-*` also runs the ECS checks.
    format!("FROM logs-* | WHERE {expr}")
}

fn eql(expr: &str) -> String {
    format!("process where {expr}")
}

#[test]
fn long_or_chains_do_not_overflow_the_stack() {
    // `FROM logs-*` also runs the ECS checks.
    on_small_stack("esql", || {
        let q = esql(&chain("a == 1", " OR ", ESQL_CHAIN_FLOOR));
        opentide_esql::analyze(&q);
    });
    on_small_stack("eql", || {
        let q = eql(&chain("a == 1", " or ", EQL_CHAIN_FLOOR));
        opentide_eql::analyze(&q);
        opentide_eql::ecs_diagnostics(&q);
    });
    on_small_stack("kuery", || {
        opentide_kuery::analyze(
            &chain("a:1", " or ", KUERY_CHAIN_FLOOR),
            opentide_lucene::parses,
        );
        opentide_kuery::ecs_diagnostics(&chain("source.port:1", " or ", KUERY_CHAIN_FLOOR));
    });
    on_small_stack("lucene", || {
        opentide_lucene::analyze(&chain("a:1", " OR ", LUCENE_CHAIN_FLOOR));
        opentide_lucene::ecs_diagnostics(&chain("source.port:1", " OR ", LUCENE_CHAIN_FLOOR));
    });
}

#[test]
fn kql_chain_floor() {
    let q = kql(&chain("a == 1", " or ", KQL_CHAIN_FLOOR));
    analyzes_cleanly_on("kql chain", KQL_STACK, q, kql_diagnostics);
}

#[test]
fn kql_nest_floor() {
    analyzes_cleanly_on(
        "kql nest",
        KQL_STACK,
        kql(&nest("a == 1", KQL_NEST_FLOOR)),
        kql_diagnostics,
    );
}

#[test]
fn spl_chain_floor() {
    let q = spl(&chain("a=1", " OR ", SPL_CHAIN_FLOOR));
    analyzes_cleanly("spl chain", q, |q| opentide_spl::analyze(q).diagnostics);
}

#[test]
fn spl_nest_floor() {
    let q = format!("index=x {}", nest("a=1", SPL_NEST_FLOOR));
    analyzes_cleanly("spl nest", q, |q| opentide_spl::analyze(q).diagnostics);
}

#[test]
fn cql_chain_floor() {
    let q = chain("a=1", " or ", CQL_CHAIN_FLOOR);
    analyzes_cleanly("cql chain", q, |q| opentide_cql::analyze(q).diagnostics);
}

#[test]
fn cql_nest_floor() {
    let q = nest("a=1", CQL_NEST_FLOOR);
    analyzes_cleanly("cql nest", q, |q| opentide_cql::analyze(q).diagnostics);
}

#[test]
fn yaral_chain_floor() {
    let q = yaral(&chain(YARAL_TERM, " or ", YARAL_CHAIN_FLOOR));
    analyzes_cleanly("yaral chain", q, |q| opentide_yaral::analyze(q).diagnostics);
}

#[test]
fn yaral_nest_floor() {
    let q = yaral(&nest(YARAL_TERM, YARAL_NEST_FLOOR));
    analyzes_cleanly("yaral nest", q, |q| opentide_yaral::analyze(q).diagnostics);
}

#[test]
fn yara_chain_floor() {
    let q = yara(&chain("$a", " or ", YARA_CHAIN_FLOOR));
    analyzes_cleanly("yara chain", q, |q| opentide_yara::analyze(q).diagnostics);
}

#[test]
fn yara_nest_floor() {
    let q = yara(&nest("$a", YARA_NEST_FLOOR));
    analyzes_cleanly("yara nest", q, |q| opentide_yara::analyze(q).diagnostics);
}

#[test]
fn datadog_chain_floor() {
    // An implied AND chain and an OR chain: each one flat node.
    for (term, op) in [("@evt.outcome:FAILURE", " OR "), ("source:okta", " ")] {
        let q = chain(term, op, DATADOG_CHAIN_FLOOR);
        analyzes_cleanly("datadog chain", q, |q| {
            opentide_datadog::analyze(q).diagnostics
        });
    }
}

#[test]
fn datadog_nest_floor() {
    for q in [
        nest("@evt.outcome:FAILURE", DATADOG_NEST_FLOOR),
        format!("@a:{}", nest("b", DATADOG_NEST_FLOOR)),
    ] {
        analyzes_cleanly("datadog nest", q, |q| {
            opentide_datadog::analyze(q).diagnostics
        });
    }
}

/// Far past the limit: one parse error, no overflow, no quadratic time.
#[test]
fn datadog_nest_past_its_limit_is_one_error() {
    for q in [
        nest("a", 100_000),
        "(".repeat(200_000),
        "@a:(".repeat(50_000),
        "-(".repeat(100_000),
    ] {
        let diagnostics = on_small_stack("datadog nest past the limit", move || {
            opentide_datadog::analyze(&q).diagnostics
        });
        let errors: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.code.ends_with("_parse_error"))
            .collect();
        assert_eq!(errors.len(), 1, "{errors:?}");
    }
}

#[test]
fn exabeam_chain_floor() {
    let q = chain("vendor:\"x\"", " OR ", EXABEAM_CHAIN_FLOOR);
    analyzes_cleanly("exabeam chain", q, |q| {
        opentide_exabeam::analyze(q).diagnostics
    });
}

#[test]
fn exabeam_nest_floor() {
    let q = nest("vendor:\"x\"", EXABEAM_NEST_FLOOR);
    analyzes_cleanly("exabeam nest", q, |q| {
        opentide_exabeam::analyze(q).diagnostics
    });
}

#[test]
fn falco_chain_floor() {
    let q = chain("proc.name = a", " or ", FALCO_CHAIN_FLOOR);
    analyzes_cleanly("falco chain", q, |q| opentide_falco::analyze(q).diagnostics);
}

#[test]
fn falco_nest_floor() {
    let q = nest("proc.name = a", FALCO_NEST_FLOOR);
    analyzes_cleanly("falco nest", q, |q| opentide_falco::analyze(q).diagnostics);
}

#[test]
fn esql_chain_floor() {
    let q = esql(&chain("a == 1", " OR ", ESQL_CHAIN_FLOOR));
    analyzes_cleanly("esql chain", q, |q| opentide_esql::analyze(q).diagnostics);
}

#[test]
fn eql_chain_floor() {
    let q = eql(&chain("a == 1", " or ", EQL_CHAIN_FLOOR));
    analyzes_cleanly("eql chain", q, |q| opentide_eql::analyze(q).diagnostics);
}

#[test]
fn kuery_chain_floor() {
    let q = chain("a:1", " or ", KUERY_CHAIN_FLOOR);
    analyzes_cleanly("kuery chain", q, |q| {
        opentide_kuery::analyze(q, opentide_lucene::parses).diagnostics
    });
}

#[test]
fn lucene_chain_floor() {
    let q = chain("a:1", " OR ", LUCENE_CHAIN_FLOOR);
    analyzes_cleanly("lucene chain", q, |q| {
        opentide_lucene::analyze(q).diagnostics
    });
}

#[test]
fn esql_nest_floor() {
    let q = esql(&nest("a == 1", ESQL_NEST_FLOOR));
    analyzes_cleanly("esql nest", q, |q| opentide_esql::analyze(q).diagnostics);
}

#[test]
fn eql_nest_floor() {
    let q = eql(&nest("a == 1", EQL_NEST_FLOOR));
    analyzes_cleanly("eql nest", q, |q| opentide_eql::analyze(q).diagnostics);
}

#[test]
fn kuery_nest_floor() {
    let q = nest("a:1", KUERY_NEST_FLOOR);
    analyzes_cleanly("kuery nest", q, |q| {
        opentide_kuery::analyze(q, opentide_lucene::parses).diagnostics
    });
}

/// kuery's `max_depth` (`opentide-kuery` `MAX_DEPTH`): the margin above
/// `KUERY_NEST_FLOOR` that keeps the floor from sitting on the limit.
const KUERY_MAX_DEPTH: usize = 1_024;

/// The limit itself, on the 1 MB stack, through `analyze` (the highlighter,
/// the checks and the rowan tree's drop walk it too): it must parse clean.
#[test]
fn kuery_nest_at_its_limit() {
    for q in [
        nest("a:1", KUERY_MAX_DEPTH),
        format!("a:{}", nest("b", KUERY_MAX_DEPTH)),
    ] {
        analyzes_cleanly("kuery nest at the limit", q, |q| {
            opentide_kuery::analyze(q, opentide_lucene::parses).diagnostics
        });
    }
}

/// Far past the limit: one parse error, no overflow, no quadratic time.
#[test]
fn kuery_nest_past_its_limit_is_one_error() {
    for q in [
        nest("a:1", 100_000),
        "(".repeat(200_000),
        "a:{".repeat(50_000),
    ] {
        let diagnostics = on_small_stack("kuery nest past the limit", move || {
            opentide_kuery::analyze(&q, opentide_lucene::parses).diagnostics
        });
        let errors: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.code.ends_with("_parse_error"))
            .collect();
        assert_eq!(errors.len(), 1, "{errors:?}");
    }
}

#[test]
fn lucene_nest_floor() {
    let q = nest("a:1", LUCENE_NEST_FLOOR);
    analyzes_cleanly("lucene nest", q, |q| {
        opentide_lucene::analyze(q).diagnostics
    });
}

/// `n` levels of `prefix`, each opening a parenthesis after the language's precedence chain
/// (`a or b and not (`), closed on `atom`.
fn ladder(prefix: &str, atom: &str, n: usize) -> String {
    format!("{}{atom}{}", prefix.repeat(n), ")".repeat(n))
}

/// One language's precedence chain inside every level of nesting (#1427).
struct Ladder {
    name: &'static str,
    /// The query around the expression.
    wrap: fn(&str) -> String,
    /// A level: `or`, `and`, `not` and an opening parenthesis.
    prefix: &'static str,
    atom: &'static str,
    /// The deepest ladder that must analyse cleanly: the nesting floor, or, where the
    /// language's grammar spends more than one of its `max_depth` levels on a step of
    /// the chain (a recursive `not`, a precedence level), its limit for this shape.
    clean: usize,
    analyze: fn(&str) -> Vec<Diagnostic>,
}

/// The diagnostics that say the engine stopped: a parse error, or a depth limit of its own.
fn stopped(diagnostics: &[Diagnostic]) -> Vec<&str> {
    diagnostics
        .iter()
        .map(|d| d.code.as_str())
        .filter(|code| {
            code.ends_with("_parse_error")
                || ((code.contains("depth") || code.contains("deep"))
                    && !VENDOR_DEPTH_CODES.contains(code))
        })
        .collect()
}

/// The contract of ADR 0012's depth section, on each pure-Rust parser: the floor is
/// defined for parenthesised nesting (the `*_nest_floor` tests), and the toolkit charges a
/// level the tree nodes it opens. With the language's precedence chain inside every level,
/// a ladder analyses cleanly at the floor, or at the limit its own grammar sets for the
/// shape; far past it, the engine stops with one error: never an abort, never more.
#[test]
fn a_precedence_chain_in_each_level_stops_with_one_error() {
    let ladders = [
        Ladder {
            name: "kql",
            wrap: kql,
            prefix: "a == 1 or b == 2 and not(",
            atom: "c == 3",
            clean: KQL_NEST_FLOOR,
            analyze: kql_diagnostics,
        },
        Ladder {
            name: "spl",
            wrap: |e| format!("index=x {e}"),
            prefix: "a=1 OR b=2 AND NOT (",
            atom: "c=3",
            clean: SPL_NEST_FLOOR,
            analyze: |q| opentide_spl::analyze(q).diagnostics,
        },
        // `not` is a level of CQL's `max_depth` (1,000): two a step.
        Ladder {
            name: "cql",
            wrap: str::to_string,
            prefix: "a=1 or b=2 and not (",
            atom: "c=3",
            clean: 500,
            analyze: |q| opentide_cql::analyze(q).diagnostics,
        },
        // `not` is a level of YARA-L's `max_depth` (1,100): two a step.
        Ladder {
            name: "yaral",
            wrap: yaral,
            prefix: "$e.principal.ip = \"y\" or $e.target.ip = \"z\" and not (",
            atom: YARAL_TERM,
            clean: 549,
            analyze: |q| opentide_yaral::analyze(q).diagnostics,
        },
        // `NOT` is a level of Exabeam's `max_depth` (200): two a step.
        Ladder {
            name: "exabeam",
            wrap: str::to_string,
            prefix: "vendor:\"x\" OR vendor:\"y\" AND NOT (",
            atom: "vendor:\"z\"",
            clean: 99,
            analyze: |q| opentide_exabeam::analyze(q).diagnostics,
        },
        // Only a group is a level of the Datadog grammar's `max_depth`; a level opens four
        // nodes (OR, AND, NOT, the group), under the toolkit's budget at the floor.
        Ladder {
            name: "datadog",
            wrap: str::to_string,
            prefix: "a:1 OR b:2 AND NOT (",
            atom: "c:3",
            clean: DATADOG_NEST_FLOOR,
            analyze: |q| opentide_datadog::analyze(q).diagnostics,
        },
        Ladder {
            name: "falco",
            wrap: str::to_string,
            prefix: "proc.name = a or proc.name = b and not (",
            atom: "proc.name = c",
            clean: FALCO_NEST_FLOOR,
            analyze: |q| opentide_falco::analyze(q).diagnostics,
        },
        // ES|QL's descent enters a level for `OR`, `AND`, `NOT` and the parenthesis:
        // four of its 1,100 a step.
        Ladder {
            name: "esql",
            wrap: esql,
            prefix: "a == 1 OR b == 2 AND NOT (",
            atom: "c == 3",
            clean: 274,
            analyze: |q| opentide_esql::analyze(q).diagnostics,
        },
        // EQL's likewise: four of its 1,024 a step.
        Ladder {
            name: "eql",
            wrap: eql,
            prefix: "a == 1 or b == 2 and not (",
            atom: "c == 3",
            clean: 255,
            analyze: |q| opentide_eql::analyze(q).diagnostics,
        },
        Ladder {
            name: "kuery",
            wrap: str::to_string,
            prefix: "a:1 or b:2 and not (",
            atom: "c:3",
            clean: KUERY_NEST_FLOOR,
            analyze: |q| opentide_kuery::analyze(q, opentide_lucene::parses).diagnostics,
        },
        Ladder {
            name: "lucene",
            wrap: str::to_string,
            prefix: "a:1 OR b:2 AND NOT (",
            atom: "c:3",
            clean: LUCENE_NEST_FLOOR,
            analyze: |q| opentide_lucene::analyze(q).diagnostics,
        },
    ];
    for l in ladders {
        let stack = if l.name == "kql" {
            KQL_STACK
        } else {
            SMALL_STACK
        };
        let query = (l.wrap)(&ladder(l.prefix, l.atom, l.clean));
        analyzes_cleanly_on(l.name, stack, query, l.analyze);
        let far = (l.wrap)(&ladder(l.prefix, l.atom, 5_000));
        let analyze = l.analyze;
        let diagnostics = on_stack(l.name, stack, move || analyze(&far));
        let stopped = stopped(&diagnostics);
        assert_eq!(stopped.len(), 1, "{}: {stopped:?}", l.name);
    }
}

/// SPL's eval chain through every precedence inside each call, closed by two parentheses a
/// level: `f(a OR b AND NOT c == d + e * -(`. It aborted a 1 MB stack at 450 levels, the
/// operands recursing unchecked (#1473); each step is now six of SPL's 1,024 levels.
fn spl_eval_ladder(n: usize) -> String {
    format!(
        "index=x | eval z={}1{}",
        "f(a OR b AND NOT c == d + e * -(".repeat(n),
        "))".repeat(n)
    )
}

/// The eval ladder analyses cleanly at the limit its six levels a step leave (170, which
/// take 1,020 of 1,024), and past it, up to a million characters of it, is one parse error:
/// never an abort, and linear.
#[test]
fn spl_eval_ladder_stops_with_one_error() {
    analyzes_cleanly("spl eval ladder", spl_eval_ladder(170), |q| {
        opentide_spl::analyze(q).diagnostics
    });
    let step = "f(a OR b AND NOT c == d + e * -(".len() + "))".len();
    for n in [171, 450, 1_000_000 / step] {
        let q = spl_eval_ladder(n);
        let diagnostics = on_small_stack("spl eval ladder past", move || {
            opentide_spl::analyze(&q).diagnostics
        });
        let stopped = stopped(&diagnostics);
        assert_eq!(stopped.len(), 1, "{n}: {stopped:?}");
    }
}
