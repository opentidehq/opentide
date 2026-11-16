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
            started.elapsed() < Duration::from_secs(20),
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
