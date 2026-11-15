//! The differential harness on a toy old/new pair with known differences.

use opentide_parse::differential::{
    Class, Config, Engine, Report, Source, Surfaces, assert_gates, run,
};
use std::ops::Range;

/// A toy engine: valid means balanced parentheses. The `tweak` makes the
/// "new" engine differ in one way.
#[derive(Clone, Copy, PartialEq)]
enum Tweak {
    None,
    /// A different message on unbalanced input.
    BrokenMessage,
    /// A different token count when the input has a `é`.
    ValidTokens,
    /// An unbalanced input is judged valid.
    Verdict,
    /// A different hover at every offset.
    Hover,
}

struct Toy(Tweak);

fn balanced(text: &str) -> bool {
    let mut depth = 0_i32;
    for c in text.chars() {
        depth += i32::from(c == '(') - i32::from(c == ')');
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

impl Engine for Toy {
    fn observe(&self, input: &str) -> Surfaces {
        let ok = balanced(input);
        let diag = match (ok, self.0) {
            (true, _) => String::new(),
            (false, Tweak::BrokenMessage) => "unbalanced: expected `)`".to_owned(),
            (false, Tweak::Verdict) => String::new(),
            (false, _) => "unbalanced".to_owned(),
        };
        let extra = usize::from(self.0 == Tweak::ValidTokens && input.contains('é'));
        vec![
            ("diagnostics".to_owned(), diag),
            (
                "tokens".to_owned(),
                (tokens(input).len() + extra).to_string(),
            ),
        ]
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        // Slicing panics off a char boundary: the harness must never pass one.
        let before = input[..offset].chars().count();
        let hover = if self.0 == Tweak::Hover {
            before + 1
        } else {
            before
        };
        vec![("hover".to_owned(), hover.to_string())]
    }
}

fn tokens(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        if c == ' ' || c == '(' || c == ')' {
            if let Some(s) = start.take() {
                out.push(s..i);
            }
            if c != ' ' {
                out.push(i..i + 1);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push(s..text.len());
    }
    out
}

fn files() -> Vec<Source> {
    [
        "(a b) c",
        "((a) (b))",
        "(unclosed (x)",
        "é ((😀))\nsecond line (z)",
    ]
    .iter()
    .enumerate()
    .map(|(i, t)| Source {
        name: format!("f{i}"),
        text: (*t).to_owned(),
    })
    .collect()
}

fn go(tweak: Tweak, tune: impl FnOnce(&mut Config<'_>)) -> Report {
    let verdict = |s: &Surfaces| s.iter().any(|(n, v)| n == "diagnostics" && v.is_empty());
    let samples = ["(", ")", "a", "é", "(b)"];
    let mut config = Config::new(&verdict, &tokens, &samples);
    tune(&mut config);
    run(&Toy(Tweak::None), &Toy(tweak), &files(), &config)
}

fn count(report: &Report, surface: &str, class: Class) -> usize {
    report
        .entries
        .get(&(surface.to_owned(), class))
        .map_or(0, |e| e.count)
}

#[test]
fn identical_engines_pass_and_cover_valid_and_broken_inputs() {
    let report = go(Tweak::None, |_| {});
    assert!(report.entries.is_empty(), "{:?}", report.entries.keys());
    assert!(
        report.valid > 50 && report.inputs > report.valid + 50,
        "{report:?}"
    );
    assert_gates(&report);
}

#[test]
fn message_changes_on_broken_input_are_counted_and_listed_not_failed() {
    let report = go(Tweak::BrokenMessage, |c| c.max_examples = 3);
    let entry = &report.entries[&("diagnostics".to_owned(), Class::Broken)];
    assert!(
        entry.count > 3,
        "every difference is counted: {}",
        entry.count
    );
    assert_eq!(entry.examples.len(), 3, "examples are capped");
    assert_eq!(entry.examples[0].old, "unbalanced");
    assert_eq!(report.total(Class::Valid) + report.total(Class::Verdict), 0);
    assert_gates(&report);
}

#[test]
#[should_panic(expected = "differential gates failed")]
fn a_difference_on_valid_input_fails_the_gate() {
    let report = go(Tweak::ValidTokens, |_| {});
    assert!(count(&report, "tokens", Class::Valid) > 0);
    assert_gates(&report);
}

#[test]
fn a_verdict_change_on_broken_input_fails_with_a_readable_summary() {
    let report = go(Tweak::Verdict, |_| {});
    assert!(count(&report, "verdict", Class::Verdict) > 0);
    let panic = std::panic::catch_unwind(|| assert_gates(&report)).unwrap_err();
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        message.contains("`verdict`") && message.contains("old:"),
        "{message}"
    );
}

#[test]
fn offset_surfaces_are_compared_at_char_boundaries_and_sampled_above_the_cap() {
    let all = go(Tweak::Hover, |c| c.max_offsets = 10_000);
    let sampled = go(Tweak::Hover, |c| c.max_offsets = 4);
    let (a, s) = (
        count(&all, "hover", Class::Valid),
        count(&sampled, "hover", Class::Valid),
    );
    assert!(s > 0 && s < a, "sampled {s} < all {a}");
    // 4 offsets per input at most, plus the end.
    assert!(s + count(&sampled, "hover", Class::Broken) <= sampled.inputs * 5);
}

#[test]
fn a_run_is_deterministic_and_the_seed_changes_the_inputs() {
    let one = go(Tweak::BrokenMessage, |_| {});
    assert_eq!(one, go(Tweak::BrokenMessage, |_| {}));
    let other = go(Tweak::BrokenMessage, |c| c.seed = 99);
    assert_ne!(one.inputs, 0);
    assert_ne!(one, other);
}

#[test]
fn the_json_report_has_totals_and_examples_and_is_written_where_asked() {
    let report = go(Tweak::BrokenMessage, |_| {});
    let json = report.to_json();
    assert_eq!(json["inputs"]["total"], report.inputs);
    let diff = &json["differences"][0];
    assert_eq!(
        (diff["surface"].as_str(), diff["class"].as_str()),
        (Some("diagnostics"), Some("broken"))
    );
    assert!(
        diff["examples"][0]["new"]
            .as_str()
            .is_some_and(|m| m.contains("expected"))
    );

    let dir = std::env::temp_dir().join(format!("opentide-parse-diff-{}", std::process::id()));
    let path = dir.join("nested").join("report.json");
    report.write_json(&path).unwrap();
    let back: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(back, json);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn empty_inputs_samples_and_files_do_not_panic() {
    let verdict = |_: &Surfaces| true;
    // A lexer that lies: reversed, out of bounds and mid-character ranges.
    let lexer = |_: &str| vec![Range { start: 5, end: 2 }, 0..99, 1..2];
    let config = Config::new(&verdict, &lexer, &[]);
    let report = run(&Toy(Tweak::None), &Toy(Tweak::None), &[], &config);
    assert_eq!(report.inputs, 0);
    let multibyte = [Source {
        name: "m".into(),
        text: "éé😀 (é)".into(),
    }];
    assert_gates(&run(
        &Toy(Tweak::None),
        &Toy(Tweak::None),
        &multibyte,
        &config,
    ));
    let empty = [Source {
        name: "e".into(),
        text: String::new(),
    }];
    assert_gates(&run(&Toy(Tweak::None), &Toy(Tweak::None), &empty, &config));
}
