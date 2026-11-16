//! The analysis on the parser's tree, through the crate's public functions (#1425 review): long
//! arithmetic runs on a 1 MB stack, many comments in linear time, broken input no noisier than
//! its syntax error, and highlighting that still reads names and literals after a typo.

use opentide_eql::{analyze, completions, ecs_diagnostics, hover, sequences, signature_help};
use std::time::{Duration, Instant};

/// Runs `f` on a 1 MB stack, as the browser module does.
fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(f)
        .map(std::thread::JoinHandle::join)
        .unwrap_or_else(|e| panic!("spawn: {e}"))
        .unwrap_or_else(|_| panic!("overflowed or panicked"))
}

/// A run of `+ - * / %` is 20,000 levels deep once nested to the left, as tree-sitter nested
/// it; the operand types are folded in a loop (it overflowed at 3,000 terms, tree-sitter too).
#[test]
fn a_long_arithmetic_run_is_analysed_on_a_small_stack() {
    for op in [" + ", " - ", " * ", " / ", " % "] {
        let source = format!("process where a == {}", vec!["1"; 20_000].join(op));
        let started = Instant::now();
        let errors = on_small_stack(move || {
            let result = analyze(&source);
            let _ = ecs_diagnostics(&source);
            let _ = sequences(&source);
            let _ = hover(&source, source.len() - 1);
            let _ = completions(&source, source.len());
            let _ = signature_help(&source, source.len());
            result
                .diagnostics
                .iter()
                .filter(|d| d.code == "eql_parse_error")
                .count()
        });
        assert_eq!(errors, 0, "{op}");
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{op}: {:?}",
            started.elapsed()
        );
    }
}

/// Fails unless `run(4 * n)` takes less than 8 times `run(n)`: linear work
/// takes 4 times as long, quadratic 16 times. Each is the best of three runs,
/// the sizes alternated, so a busy machine slows both alike; a run under 50 ms passes whatever the
/// ratio, its noise being larger than it.
fn assert_linear(name: &str, n: usize, run: impl Fn(usize)) {
    let time = |k: usize| {
        let started = Instant::now();
        run(k);
        started.elapsed()
    };
    // Alternated, so that a busy spell slows both sizes alike.
    let (mut small, mut large) = (Duration::MAX, Duration::MAX);
    for _ in 0..3 {
        small = small.min(time(n));
        large = large.min(time(4 * n));
    }
    assert!(
        large < Duration::from_millis(50) || large < small * 8,
        "{name}: {small:?} for {n}, {large:?} for {}: not linear",
        4 * n
    );
}

/// The analysis's steps for `run(make(n))` and `run(make(4 * n))`: fails unless the larger
/// takes fewer than 8 times the smaller's, where linear work takes 4 times and quadratic 16.
/// Steps are counted on the thread that runs (`opentide_eql::steps`), not timed, so the check
/// is deterministic.
fn assert_steps_linear(name: &str, n: usize, make: impl Fn(usize) -> String, run: impl Fn(&str)) {
    let steps = |k: usize| {
        let source = make(k);
        let before = opentide_eql::steps();
        run(&source);
        opentide_eql::steps() - before
    };
    let (small, large) = (steps(n), steps(4 * n));
    assert!(small > 0, "{name}: no steps counted");
    assert!(
        large < small * 8,
        "{name}: {small} steps for {n}, {large} for {}: not linear",
        4 * n
    );
}

/// Comments are placed in their nodes in one pass: 40,000 of them took about 8 s when each was
/// inserted on its own (quadratic).
#[test]
fn many_comments_are_placed_in_linear_time() {
    let source = |n: usize| format!("process where a == 1 and {}b == 2", "/* c */ ".repeat(n));
    let full = source(40_000);
    let result = on_small_stack(move || analyze(&full));
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|d| d.code == "eql_parse_error"),
        "{:?}",
        result.diagnostics.first()
    );
    assert_linear("comments", 10_000, |n| {
        let text = source(n);
        let _ = on_small_stack(move || analyze(&text));
    });
}

/// An unfinished call is its syntax error alone: no arity or argument-type finding for the
/// fragment, as the tree-sitter engine had none.
#[test]
fn an_unfinished_expression_is_only_its_syntax_error() {
    for source in [
        "process where startsWith(a, ".to_string(),
        "process where length(".to_string(),
        "process where cidrMatch(source.ip, ".to_string(),
        "process where a + ".to_string(),
        format!("process where {}a", "length(".repeat(1_500)),
    ] {
        let codes: Vec<String> = on_small_stack({
            let source = source.clone();
            move || {
                analyze(&source)
                    .diagnostics
                    .into_iter()
                    .map(|d| d.code)
                    .collect()
            }
        });
        let head: String = source.chars().take(40).collect();
        assert!(
            codes
                .iter()
                .all(|c| c == "eql_parse_error" || c == "eql_expression_depth"),
            "{head}: {codes:?}"
        );
        assert!(codes.len() <= 2, "{head}: {codes:?}");
    }
}

/// After a typo, names, strings and numbers keep their highlight.
#[test]
fn a_broken_query_still_highlights_its_names_and_literals() {
    let source = "process wehre a == 1 and b == \"x\"";
    let tokens = analyze(source).tokens;
    let capture_of = |text: &str| {
        let start = source.find(text).unwrap_or(usize::MAX);
        tokens
            .iter()
            .find(|t| t.span.start == start)
            .map(|t| t.capture.clone())
    };
    for (text, capture) in [("1", "number"), ("\"x\"", "string")] {
        assert_eq!(capture_of(text).as_deref(), Some(capture), "{text}");
    }
    let names = tokens.iter().filter(|t| t.capture == "variable").count();
    assert!(names >= 2, "{tokens:?}");
}

/// A run with a doubled or trailing operator highlights each token once (the tree-sitter-shaped
/// view re-nested such a run and emitted a whole operand twice).
#[test]
fn a_broken_run_highlights_each_token_once() {
    for source in [
        "process where a and b and",
        "process where x and y and and b",
        "process where a in~ (\"a\") and b like~ \"*.dll\" and",
    ] {
        let tokens = analyze(source).tokens;
        let mut spans: Vec<_> = tokens.iter().map(|t| (t.span.start, t.span.end)).collect();
        let all = spans.len();
        spans.sort_unstable();
        spans.dedup();
        assert_eq!(spans.len(), all, "{source}: {tokens:?}");
    }
}

/// A pipe whose name or arguments the parser could not read is its syntax error alone: no
/// `unrecognized pipe` naming the error region, no argument count over it.
#[test]
fn a_broken_pipe_is_only_its_syntax_error() {
    for source in [
        "process where true | in head 5",
        "process where process.pid =| = \"4624\"",
        "\"dns\" where (false) | tail 10\n\"dns\" where (false) | tail 10",
        // A sample's pipe with no name is not also a pipe on a sample.
        "sample by a [a where true] [b where true] | (",
        // An argument that is an error region is not counted.
        "process where true | head 1 x",
    ] {
        let codes: Vec<String> = analyze(source)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect();
        assert_eq!(codes, ["eql_parse_error"], "{source}");
    }
}

/// Whether a comparison is translated to a query is decided once per run level, not by
/// climbing a long `or` run again for each comparison in it: 40,000 of them stay linear.
#[test]
fn a_long_run_of_field_comparisons_is_linear() {
    let source = format!(
        "process where {} or true",
        vec!["a == b"; 40_000].join(" or ")
    );
    let errors = on_small_stack(move || analyze(&source).diagnostics.len());
    assert_eq!(errors, 0, "an `or` with `true` is folded away");
    assert_steps_linear(
        "field comparisons",
        2_000,
        |n| format!("process where {} or true", vec!["a == b"; n].join(" or ")),
        |q| drop(analyze(q)),
    );
}

/// A run with a trailing or doubled operator reports each finding once: the tree-sitter-shaped
/// view nested such a run so that its last operand stood under two levels, and checked it
/// twice.
#[test]
fn a_broken_run_reports_each_finding_once() {
    for source in [
        "process where a == 1 or b == c or",
        "process where a == b or c == d or e == f or",
        "process where a == b and c == d and",
        "process where (c == d or or e == f) or",
    ] {
        let diagnostics = analyze(source).diagnostics;
        let mut seen: Vec<String> = diagnostics.iter().map(|d| format!("{d:?}")).collect();
        let all = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), all, "{source}: {diagnostics:#?}");
        assert!(
            diagnostics.iter().any(|d| d.code == "eql_field_comparison"),
            "{source}: {diagnostics:#?}"
        );
    }
}

/// Arithmetic nested in parentheses, `((1 + 1) + 1) …`, is typed once per run: each run is the
/// left operand of the run around it, and was typed again at each depth.
#[test]
fn nested_arithmetic_is_linear() {
    assert_steps_linear(
        "nested arithmetic",
        100,
        |n| format!("process where {}1{} == 1", "(".repeat(n), " + 1)".repeat(n)),
        |q| drop(analyze(q)),
    );
}

/// A chain of `not` is spanned only when the parser found a problem: each `not` was spanned
/// down to its comparison, quadratic in the chain.
#[test]
fn a_long_chain_of_not_is_linear() {
    assert_steps_linear(
        "chained not",
        100,
        |n| format!("process where {}a == 1", "not ".repeat(n)),
        |q| drop(analyze(q)),
    );
}
