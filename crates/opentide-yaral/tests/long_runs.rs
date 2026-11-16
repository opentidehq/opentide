//! Every analysis entry point on a 1 MB stack (the browser WASM module's)
//! over a million repeats of each token class and over deep input: the
//! diagnostics of the three contexts, the highlight tokens, the profile,
//! hover, completions and signature help (#1227). The checks walk the tree
//! in loops, never one frame per level, and stay linear in the input.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_yaral::editor::{completions, hover, signature_help};
use opentide_yaral::{Context, analyze_with, infer_profile};
use std::thread;
use std::time::{Duration, Instant};

/// Every entry point on `source`, on a 1 MB stack; the diagnostics of a file.
fn every_entry_point(source: String) -> Vec<opentide_core::Diagnostic> {
    thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let mut file = Vec::new();
            for ctx in [Context::FILE, Context::SECTIONS, Context::SEARCH] {
                let analysis = analyze_with(&source, &ctx);
                if ctx.profile.is_none() {
                    file = analysis.diagnostics;
                }
            }
            let _ = infer_profile(&source);
            for at in [0, source.len() / 2, source.len().saturating_sub(1)] {
                let at = source.floor_char_boundary(at);
                let _ = hover(&source, at);
                let _ = completions(&source, at);
                let _ = signature_help(&source, at);
            }
            file
        })
        .expect("a thread")
        .join()
        .expect("the analysis overflowed or panicked")
}

/// In a rule's `events`.
fn rule(expr: &str) -> String {
    format!(
        "rule r {{\n  meta:\n    author = \"x\"\n  events:\n    {expr}\n  condition:\n    $e\n}}\n"
    )
}

/// A million repeats of each token class, one test each (nextest runs them
/// in parallel; each takes 10 to 30 s in a debug build). Linear: a quadratic
/// step, as the UTF-16 columns of one long line were, takes minutes.
const N: usize = 1_000_000;

macro_rules! a_million {
    ($($name:ident: $source:expr;)*) => {$(
        #[test]
        fn $name() {
            let started = Instant::now();
            every_entry_point($source);
            assert!(
                started.elapsed() < Duration::from_secs(240),
                "{:?}",
                started.elapsed()
            );
        }
    )*};
}

a_million! {
    string_escapes: format!("\"{}\"", "\\a".repeat(N));
    regex_escapes: format!("/{}/", "\\a".repeat(N));
    raw_string: format!("`{}`", "a".repeat(N));
    block_comment: format!("/*{}*/", "a".repeat(N));
    line_comment: format!("// {}", "a".repeat(N));
    names: "a ".repeat(N);
    variables: "$a ".repeat(N);
    counts: "#e ".repeat(N);
    reference_lists: "%l ".repeat(N);
    integers: "1 ".repeat(N);
    floats: "1.5 ".repeat(N);
    durations: "10m ".repeat(N);
    spaces: " ".repeat(N);
    no_break_spaces: "\u{a0}".repeat(N);
    unterminated_strings: "\"\u{e9}".repeat(N);
    non_ascii_letters: "\u{e9}".repeat(N);
    rule_keywords: "rule ".repeat(N);
    section_labels: "events: ".repeat(N);
    and_keywords: "and ".repeat(N);
    open_parentheses: "( ".repeat(N);
    close_parentheses: ") ".repeat(N);
    open_braces: "{ ".repeat(N);
    close_braces: "} ".repeat(N);
    open_brackets: "[ ".repeat(N);
    commas: ", ".repeat(N);
    dots: ". ".repeat(N);
    equals: "= ".repeat(N);
    not_equals: "!= ".repeat(N);
    less_or_equal: "<= ".repeat(N);
    minus_signs: "- ".repeat(N);
    bangs: "! ".repeat(N);
    open_calls: "f( ".repeat(N);
}

/// Deep valid input analyses with no syntax error.
#[test]
fn deep_valid_input_is_clean() {
    let term = "$e.principal.hostname = \"x\"";
    for expr in [
        format!("{}{term}{}", "(".repeat(1_000), ")".repeat(1_000)),
        vec![term; 20_000].join(" or "),
        vec![term; 20_000].join(" and "),
        format!("$e.a = {}", vec!["1"; 20_000].join(" + ")),
        format!("{}{term}", "not ".repeat(1_000)),
        format!("$e.a = {}1", "-".repeat(1_000)),
        format!(
            "$e.a = {}$e.b{}",
            "strings.to_lower(".repeat(500),
            ")".repeat(500)
        ),
        vec![term; 4_000].join("\n    "),
        // Comparisons nest to the left, one tree level each (as on
        // tree-sitter): 4,000 stays under the toolkit's 4,096 levels.
        vec!["$e.a"; 4_000].join(" = "),
    ] {
        let found = every_entry_point(rule(&expr));
        assert!(
            !found.iter().any(|d| d.code == "yaral_parse_error"),
            "{}: {found:?}",
            &expr[..40.min(expr.len())]
        );
    }
}

/// An outcome's value in a rule with `match` is checked for aggregations
/// over every node: a run of 4,000 comparisons (4,000 tree levels) inside
/// `max(...)`, `if(...)` or parentheses overflowed a 1 MB stack when the
/// check recursed per level (#1227 review).
#[test]
fn deep_outcome_values_with_match_are_clean() {
    let chain = vec!["$e.principal.ip"; 4_000].join(" = ");
    for value in [
        format!("max({chain})"),
        format!("max(if({chain}, 1, 0))"),
        format!("max(({chain}))"),
    ] {
        let source = format!(
            "rule r {{\n  meta:\n    author = \"x\"\n  events:\n    $e.principal.hostname = $h\n  match:\n    $h over 5m\n  outcome:\n    $x = {value}\n  condition:\n    $e\n}}\n"
        );
        let found = every_entry_point(source);
        assert!(
            !found.iter().any(|d| d.code == "yaral_parse_error"),
            "{found:?}"
        );
    }
}

/// Past the limits, one syntax error each and no overflow: 1,100 levels of
/// nesting, and the toolkit's 4,096 tree levels (a run of comparisons).
#[test]
fn past_the_limits_there_is_one_error() {
    let term = "$e.principal.hostname = \"x\"";
    for (expr, message) in [
        (
            format!("{}{term}{}", "(".repeat(5_000), ")".repeat(5_000)),
            "nesting deeper than 1100 levels",
        ),
        (
            format!("{}{term}", "not ".repeat(200_000)),
            "nesting deeper than 1100 levels",
        ),
        (
            format!("{}1{}", "[".repeat(5_000), "]".repeat(5_000)),
            "nesting deeper than 1100 levels",
        ),
        (
            vec!["$e.a"; 5_000].join(" = "),
            "the syntax tree nests deeper than 4096 nodes",
        ),
    ] {
        let found = every_entry_point(rule(&expr));
        let errors: Vec<_> = found
            .iter()
            .filter(|d| d.code == "yaral_parse_error")
            .collect();
        assert!(
            matches!(errors.as_slice(), [e] if e.message.contains(message)),
            "{}: {found:?}",
            &expr[..40.min(expr.len())]
        );
    }
}
