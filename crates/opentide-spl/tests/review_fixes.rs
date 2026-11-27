//! Findings of the independent review of the first PRs: `(text, the parser
//! accepts it)`, each the verdict tree-sitter gave the same text when the
//! parser replaced it.

mod support;

use opentide_spl::syntax::parse;
use support::render;

fn same_verdict(queries: &[(&str, bool)]) {
    let mut wrong = Vec::new();
    for &(query, accepted) in queries {
        let ours = parse(query).1.errors.is_empty();
        if ours != accepted {
            wrong.push(format!(
                "{query:?}: the parser {}, expected {}\n{}",
                if ours { "accepts" } else { "rejects" },
                if accepted { "accepted" } else { "rejected" },
                render(query)
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_subsearch_that_starts_with_a_macro_and_has_terms_is_a_search() {
    same_verdict(&[
        ("a [ `m` earliest=-1d ]", true),
        ("a [ `m` \"foo\" ]", true),
        ("a [ `m` host=x ]", true),
        ("a [ `m` NOT b ]", true),
        ("a [ `m` ]", true),
        ("a [ `m` | head 1 ]", true),
        ("a [ | `m` x=1 ]", true),
    ]);
}

#[test]
fn value_lists_take_one_comma_between_values() {
    same_verdict(&[
        ("x IN (1,2,)", false),
        ("x IN (,1)", false),
        ("x IN (1,,2)", false),
        ("x IN (1,2)", true),
        ("x IN (1 2)", true),
        ("x IN ()", false),
        ("x IN (1,", false),
    ]);
}

#[test]
fn in_is_a_keyword_after_a_field() {
    same_verdict(&[
        ("a IN b", false),
        ("a IN", false),
        ("IN IN", false),
        ("a IN 1", false),
        ("IN", true),
        ("IN (1)", true),
        ("a IN (1)", true),
        ("x=1 IN (2)", true),
    ]);
}

#[test]
fn reserved_words_are_no_command_names() {
    same_verdict(&[
        ("| AND", false),
        ("| OR", false),
        ("| NOT", false),
        ("[ AND ]", false),
        ("a [ OR ]", false),
        ("a | AND b", false),
        ("| and", true),
        ("| or x", true),
    ]);
}

#[test]
fn an_unknown_command_may_be_a_field_word() {
    same_verdict(&[
        ("| a-b", true),
        ("| a*", true),
        ("[ | a-b ]", true),
        ("a | b-c x=1", true),
        ("| a-b | head 1", true),
        ("| {x}", false),
        ("| 1a", false),
    ]);
}

#[test]
fn a_directive_after_an_operator_or_a_loose_operator() {
    same_verdict(&[
        ("a=TERM(x)", true),
        ("== TERM(x)", true),
        ("a == TERM(x)", true),
        ("TERM( (", false),
        ("TERM(x) y", true),
        ("a=CASE(x) b", true),
        ("a!=TERM(x)", true),
        ("TERM(", true),
        ("TERM((", false),
    ]);
}

#[test]
fn command_words_glue_like_tree_sitter() {
    same_verdict(&[
        ("| fiel-ds", true),
        ("| st*ats", true),
        ("| head-x", false),
        ("| table-a b", false),
        ("| a.b c", true),
        ("| a:b", true),
    ]);
}

/// Fails unless `run(4 * n)` takes less than 8 times `run(n)`: linear work
/// takes 4 times as long, quadratic 16 times. Each is the best of three runs,
/// the sizes alternated, so a busy machine slows both alike; a run under 50 ms passes whatever the
/// ratio, its noise being larger than it. A growth over the bound is measured again, up to three
/// times, as `opentide-parse`'s `token_cache` test does: quadratic work exceeds it every time, one
/// burst of load on a shared runner does not.
fn assert_linear(name: &str, n: usize, run: impl Fn(usize)) {
    let time = |k: usize| {
        let started = std::time::Instant::now();
        run(k);
        started.elapsed()
    };
    let mut seen = Vec::new();
    for _ in 0..3 {
        // Alternated, so that a busy spell slows both sizes alike.
        let (mut small, mut large) = (std::time::Duration::MAX, std::time::Duration::MAX);
        for _ in 0..3 {
            small = small.min(time(n));
            large = large.min(time(4 * n));
        }
        if large < std::time::Duration::from_millis(50) || large < small * 8 {
            return;
        }
        seen.push((small, large));
    }
    panic!(
        "{name}: not linear from {n} to {} in any of 3 measurements: {seen:?}",
        4 * n
    );
}

#[test]
fn a_run_of_equals_after_a_command_is_linear() {
    assert_linear("a run of equals", 5_000, |n| {
        let _ = parse(&format!("| stats {}", "a=".repeat(n)));
    });
}

#[test]
fn second_review_comparisons_do_not_chain_after_and_or() {
    same_verdict(&[
        ("| where a and b = c = d", false),
        ("| where a or b < c > d", false),
        ("| where a<b and c<d<e", false),
        ("| where a<b or c<d<e", false),
        ("| eval x=a and b == c != d", false),
        ("| where (a and b = c = d)", false),
        ("| where a<b and c<d", true),
        ("| where a + b = c and d", true),
        ("| where a * b = c or d = e", true),
    ]);
}

#[test]
fn second_review_a_dedup_option_takes_a_name_or_a_boolean() {
    same_verdict(&[
        ("| dedup keepevents=1 a", false),
        ("| dedup keepevents=a-b a", false),
        ("| dedup keepevents=true() a", false),
        ("| dedup keepevents=true a", true),
        ("| dedup keepevents=x a", true),
    ]);
}
