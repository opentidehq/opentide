//! Every public entry point of the engine on the 1 MB stack of the browser
//! module (epic #1219's exit criteria; more on Windows and under coverage,
//! [`SMALL_STACK`]): each token class one million
//! characters long, and the deepest nesting and longest chains the parser
//! accepts and past them. None may overflow, panic or go quadratic.

use opentide_esql::{
    analyze, analyze_for, completions, ecs_diagnostics, hover, output_columns, signature_help,
    source_indices,
};
use std::thread;
use std::time::{Duration, Instant};

/// The stack the depth checks run on: the browser WASM module's 1 MB.
#[cfg(not(any(coverage, windows)))]
const SMALL_STACK: usize = 1 << 20;
/// A Windows debug build's frames are larger, and `cargo llvm-cov`'s
/// instrumentation enlarges every frame: the depths that fit 1 MB on Linux
/// overflowed the nightly's Windows engine tests. Neither binary is the WASM
/// budget, which the Linux and macOS test jobs keep enforcing at 1 MB; 8 MB is
/// a generous bound, not a measurement. The same rule as `SMALL_STACK` in
/// `crates/opentide-analysis/tests/deep_queries.rs`.
#[cfg(any(coverage, windows))]
const SMALL_STACK: usize = 8 << 20;

/// Runs every entry point over `source`, the offset ones at its start, middle
/// and end (moved back to a character boundary), on a [`SMALL_STACK`].
fn every_entry_point(source: String) {
    let head: String = source.chars().take(50).collect();
    let started = Instant::now();
    let joined = thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(move || {
            analyze(&source);
            analyze_for(&source, opentide_esql::StackTarget::parse("8.19"));
            output_columns(&source);
            source_indices(&source);
            ecs_diagnostics(&source);
            for mut offset in [0, source.len() / 2, source.len()] {
                while !source.is_char_boundary(offset) {
                    offset -= 1;
                }
                hover(&source, offset);
                completions(&source, offset);
                signature_help(&source, offset);
            }
        })
        .map(|h| h.join().is_ok())
        .unwrap_or(false);
    assert!(joined, "overflowed or panicked on `{head}…`");
    // Linear work takes a few seconds here in a debug build.
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "`{head}…` took {:?}",
        started.elapsed()
    );
}

#[test]
fn a_million_character_token_of_each_class() {
    let n = 1_000_000;
    for source in [
        format!("FROM a | EVAL {}", "a".repeat(n)),
        format!("FROM a | EVAL {}", "1".repeat(n)),
        format!("FROM a | EVAL 1.{}e5", "1".repeat(n)),
        format!("FROM a | EVAL ?{}", "p".repeat(n)),
        format!("FROM a | EVAL ??{}", "7".repeat(n)),
        format!("FROM a | KEEP {}", "a.".repeat(n / 2)),
        // A pattern of stars and text against columns the query made.
        format!("ROW b = 1 | KEEP {}", "b*".repeat(n / 2)),
        format!("ROW b = 1 | DROP {}", "*b".repeat(n / 2)),
        format!("ROW b = 1 | RENAME {} AS c", "b*".repeat(n / 2)),
        format!("FROM {}", "a-".repeat(n / 2)),
        format!("FROM logs-* | ENRICH {}", "p".repeat(n)),
        format!("FROM a | EVAL \"{}\"", "\\\"".repeat(n / 2)),
        format!("FROM a | EVAL \"{}\"", "\\q".repeat(n / 2)),
        format!("FROM a | EVAL \"\"\"{}\"\"\"", "x".repeat(n)),
        format!("FROM a | EVAL `{}`", "``".repeat(n / 2)),
        format!("FROM a | EVAL /*{}*/", "/*".repeat(n / 20)),
        format!("FROM a | EVAL // {}", "c".repeat(n)),
        format!("FROM a | WEHRE {}", "u".repeat(n)),
        format!("FROM logs-* | DISSECT a \"{}\"", "%{k} ".repeat(n / 5)),
        format!("FROM logs-* | GROK a \"{}\"", "%{IP:k} ".repeat(n / 8)),
        format!("FROM a | WHERE a LIKE \"{}\"", "*".repeat(n)),
        format!("PROMQL {}", "q".repeat(n)),
        "\u{e9}".repeat(n / 2),
    ] {
        every_entry_point(source);
    }
}

/// The nesting floor `deep_queries` holds (1,000), the parser's limit
/// (`max_depth` 1,100) and far past it, for every construct that nests, and
/// the 10,000-term chains.
#[test]
fn deep_and_long_input() {
    let wrap = |open: &str, close: &str, n: usize| {
        format!("FROM logs-* | WHERE {}1{}", open.repeat(n), close.repeat(n))
    };
    for n in [1_000, 1_090, 20_000] {
        for source in [
            wrap("(", ")", n),
            wrap("f(", ")", n / 2),
            wrap("(", "", n),
            wrap("not ", "", n),
            wrap("- ", "", n),
            wrap("[", "]", n),
            wrap("{\"k\": ", "}", n),
            wrap("a IN (", ")", n),
            format!("{}FROM a{}", "FROM b, (".repeat(n), ")".repeat(n)),
            format!("FROM a | {}WHERE x{}", "FORK (".repeat(n), ")".repeat(n)),
            format!("{}FROM a{}", "EXPLAIN (".repeat(n), ")".repeat(n)),
            format!("FROM a | WHERE x{}", "::int".repeat(n)),
        ] {
            every_entry_point(source);
        }
    }
    every_entry_point(format!(
        "FROM logs-* | WHERE {}",
        vec!["a == 1"; 10_000].join(" OR ")
    ));
    every_entry_point(format!(
        "FROM logs-* | EVAL x = {}",
        vec!["a"; 10_000].join(" + ")
    ));
    every_entry_point(format!("FROM a{}", " | WHERE a".repeat(10_000)));
    every_entry_point(format!("FROM a | KEEP {}", vec!["a"; 10_000].join(", ")));
}

/// Broken or noisy input: many parse problems and many findings. A name check
/// over every problem, and a scan from the start for every finding's line,
/// made these quadratic (minutes at 20,000).
#[test]
fn many_problems_and_many_findings() {
    let n = 20_000;
    every_entry_point(format!("FROM a | KEEP {}", "x,, ".repeat(n)));
    every_entry_point(format!("FROM a{}", " | WHERE x ==".repeat(n)));
    every_entry_point(format!("FROM a | EVAL {}", "x = , ".repeat(n)));
    every_entry_point(format!("ROW a = 1{}", " | SAMPLE 0.5".repeat(n)));
    every_entry_point(format!("FROM a | EVAL {}", vec!["f(x)"; n].join(", ")));
    every_entry_point(format!("FROM a | EVAL {}", vec!["f(x)"; n].join(",\n")));
}

/// The shortest of three runs of `run`, in seconds: a ratio of two such
/// times is the machine's speed cancelled out, and the minimum drops the
/// runs a loaded CI runner slowed down.
fn best_of_three(run: &dyn Fn()) -> f64 {
    (0..3)
        .map(|_| {
            let started = Instant::now();
            run();
            started.elapsed().as_secs_f64()
        })
        .fold(f64::INFINITY, f64::min)
}

/// One entry point, run on a query.
type EntryPoint = dyn Fn(&str);

/// Every entry point grows linearly with the findings: four times the input
/// takes about four times as long (a quadratic pass takes sixteen).
#[test]
fn findings_grow_linearly() {
    let query = |n: usize| format!("FROM a | EVAL {}", vec!["f(x)"; n].join(", "));
    let entry_points: [(&str, &EntryPoint); 5] = [
        ("analyze", &|s| drop(analyze(s))),
        ("ecs_diagnostics", &|s| drop(ecs_diagnostics(s))),
        ("output_columns", &|s| drop(output_columns(s))),
        ("hover", &|s| drop(hover(s, s.len() / 2))),
        ("completions", &|s| drop(completions(s, s.len()))),
    ];
    for (name, run) in entry_points {
        let (small, large) = (query(2_000), query(8_000));
        let ratio = best_of_three(&|| run(&large)) / best_of_three(&|| run(&small));
        assert!(ratio < 8.0, "{name}: 4x the input took {ratio:.1}x as long");
    }
}

/// An unknown name's "did you mean" scans the whole catalog. A query that
/// repeats one unknown function costs about what one with a known function
/// does: the scan runs once per name, not once per call. It ran per call,
/// and 20,000 calls took 11 s in a debug build, past the 60 s bound of
/// `many_problems_and_many_findings` on a slow CI runner.
#[test]
fn a_repeated_unknown_name_is_suggested_once() {
    let query = |name: &str| format!("FROM a | EVAL {}", vec![name; 4_000].join(", "));
    let (unknown, known) = (query("f(x)"), query("abs(x)"));
    let ratio =
        best_of_three(&|| drop(analyze(&unknown))) / best_of_three(&|| drop(analyze(&known)));
    assert!(
        ratio < 3.0,
        "unknown names took {ratio:.1}x as long as known ones"
    );
}
