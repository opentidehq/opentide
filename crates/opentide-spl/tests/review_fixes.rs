//! Findings of the independent review of the first PRs, each as the verdict
//! tree-sitter gives (accepted or an error) on the same text.

mod support;

use opentide_spl::syntax::parse;
use support::{old_accepts, render};

fn same_verdict(queries: &[&str]) {
    let mut wrong = Vec::new();
    for query in queries {
        let ours = parse(query).1.errors.is_empty();
        if ours != old_accepts(query) {
            wrong.push(format!(
                "{query:?}: new {ours}, tree-sitter {}\n{}",
                !ours,
                render(query)
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_subsearch_that_starts_with_a_macro_and_has_terms_is_a_search() {
    same_verdict(&[
        "a [ `m` earliest=-1d ]",
        "a [ `m` \"foo\" ]",
        "a [ `m` host=x ]",
        "a [ `m` NOT b ]",
        "a [ `m` ]",
        "a [ `m` | head 1 ]",
        "a [ | `m` x=1 ]",
    ]);
}

#[test]
fn value_lists_take_one_comma_between_values() {
    same_verdict(&[
        "x IN (1,2,)",
        "x IN (,1)",
        "x IN (1,,2)",
        "x IN (1,2)",
        "x IN (1 2)",
        "x IN ()",
        "x IN (1,",
    ]);
}

#[test]
fn in_is_a_keyword_after_a_field() {
    same_verdict(&[
        "a IN b",
        "a IN",
        "IN IN",
        "a IN 1",
        "IN",
        "IN (1)",
        "a IN (1)",
        "x=1 IN (2)",
    ]);
}

#[test]
fn reserved_words_are_no_command_names() {
    same_verdict(&[
        "| AND",
        "| OR",
        "| NOT",
        "[ AND ]",
        "a [ OR ]",
        "a | AND b",
        "| and",
        "| or x",
    ]);
}

#[test]
fn an_unknown_command_may_be_a_field_word() {
    same_verdict(&[
        "| a-b",
        "| a*",
        "[ | a-b ]",
        "a | b-c x=1",
        "| a-b | head 1",
        "| {x}",
        "| 1a",
    ]);
}

#[test]
fn a_directive_after_an_operator_or_a_loose_operator() {
    same_verdict(&[
        "a=TERM(x)",
        "== TERM(x)",
        "a == TERM(x)",
        "TERM( (",
        "TERM(x) y",
        "a=CASE(x) b",
        "a!=TERM(x)",
        "TERM(",
        "TERM((",
    ]);
}

#[test]
fn command_words_glue_like_tree_sitter() {
    same_verdict(&[
        "| fiel-ds",
        "| st*ats",
        "| head-x",
        "| table-a b",
        "| a.b c",
        "| a:b",
    ]);
}

#[test]
fn a_run_of_equals_after_a_command_is_linear() {
    let source = format!("| stats {}", "a=".repeat(20_000));
    let started = std::time::Instant::now();
    let _ = parse(&source);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn second_review_comparisons_do_not_chain_after_and_or() {
    same_verdict(&[
        "| where a and b = c = d",
        "| where a or b < c > d",
        "| where a<b and c<d<e",
        "| where a<b or c<d<e",
        "| eval x=a and b == c != d",
        "| where (a and b = c = d)",
        "| where a<b and c<d",
        "| where a + b = c and d",
        "| where a * b = c or d = e",
    ]);
}

#[test]
fn second_review_a_dedup_option_takes_a_name_or_a_boolean() {
    same_verdict(&[
        "| dedup keepevents=1 a",
        "| dedup keepevents=a-b a",
        "| dedup keepevents=true() a",
        "| dedup keepevents=true a",
        "| dedup keepevents=x a",
    ]);
}
