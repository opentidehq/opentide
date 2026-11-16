//! Every public entry point of the engine on the 1 MB stack of the browser
//! module (epic #1219's exit criteria): each token class one million
//! characters long, and the deepest nesting and longest chains the parser
//! accepts and past them. None may overflow, panic or go quadratic.

use opentide_esql::{
    analyze, analyze_for, completions, ecs_diagnostics, hover, output_columns, signature_help,
    source_indices,
};
use std::thread;
use std::time::{Duration, Instant};

/// Runs every entry point over `source`, the offset ones at its start, middle
/// and end (moved back to a character boundary), on a 1 MB stack.
fn every_entry_point(source: String) {
    let head: String = source.chars().take(50).collect();
    let started = Instant::now();
    let joined = thread::Builder::new()
        .stack_size(1 << 20)
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

/// An unknown name's "did you mean" scans the whole catalog, once per
/// distinct name in a query, not once per finding: it ran per finding, and
/// 20,000 calls of one unknown function took 11 s in a debug build. The
/// scans are counted (per thread), not timed, so the check is deterministic.
#[test]
fn an_unknown_name_is_suggested_once_per_query() {
    let scans = |query: &str| {
        let before = opentide_esql::suggestion_scans();
        analyze(query);
        opentide_esql::suggestion_scans() - before
    };
    let repeated = format!("FROM a | EVAL {}", vec!["f(x)"; 4_000].join(", "));
    assert_eq!(scans(&repeated), 1, "one unknown function, 4,000 calls");
    let three = format!(
        "FROM a | EVAL {}",
        ["f(x)", "g(x)", "h(x)"].repeat(1_000).join(", ")
    );
    assert_eq!(scans(&three), 3, "three unknown functions");
    let commands = format!("FROM a{}", " | WEHRE x".repeat(1_000));
    assert_eq!(scans(&commands), 1, "one unknown command, 1,000 times");
    let casts = format!("ROW x = 1 | EVAL {}", vec!["x::nope"; 1_000].join(", "));
    assert_eq!(scans(&casts), 1, "one unknown type, 1,000 casts");
    // Known names need no suggestion.
    assert_eq!(
        scans(&format!(
            "FROM a | EVAL {}",
            vec!["abs(x)"; 1_000].join(", ")
        )),
        0
    );
}
