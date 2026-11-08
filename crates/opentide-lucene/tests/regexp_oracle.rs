//! Opt-in differential check of the `/regexp/` validator against Lucene.
//!
//! Set `OPENTIDE_LUCENE_REGEXP_VERDICTS` to a file of `VERDICT<TAB>body`
//! lines, where `VERDICT` is what Lucene (with Elasticsearch's flags and work
//! limit) said about the body: `OK`, `SYNTAX ...`, `COMPLEX ...`, or (Lucene 9's
//! recursion limit) `DEPTH ...`. Bodies
//! use `\t`, `\n`, and `\\` escapes so a line holds any string.
//! `OPENTIDE_LUCENE_REGEXP_STACK=8` compares with Lucene 9.12 (Elasticsearch
//! 8.19) instead of Lucene 10 (Elasticsearch 9.x). The test
//! prints a confusion matrix and fails on any disagreement. Without the
//! variable it does nothing.

use opentide_lucene::regexp::{Stack, Verdict, check};
use std::collections::BTreeMap;

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn regexp_verdicts_match_lucene() {
    let Ok(path) = std::env::var("OPENTIDE_LUCENE_REGEXP_VERDICTS") else {
        return;
    };
    let stack = match std::env::var("OPENTIDE_LUCENE_REGEXP_STACK").as_deref() {
        Ok("8") => Stack::Es8,
        _ => Stack::Es9,
    };
    let text = std::fs::read_to_string(&path).expect("verdict file");
    let mut matrix: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut mismatches = Vec::new();
    for line in text.lines() {
        let Some((verdict, body)) = line.split_once('\t') else {
            continue;
        };
        let expected = verdict.split_whitespace().next().unwrap_or("").to_string();
        let body = unescape(body);
        let got = match check(&body, stack) {
            Verdict::Ok => "OK",
            Verdict::Invalid { .. } => "SYNTAX",
            Verdict::TooComplex => "COMPLEX",
            Verdict::TooLarge => "DEPTH",
        }
        .to_string();
        if got != expected && mismatches.len() < 40 {
            mismatches.push(format!("lucene {verdict} / engine {got}: {body:?}"));
        }
        *matrix.entry((expected, got)).or_default() += 1;
    }
    println!("(lucene, engine) -> count: {matrix:?}");
    for m in &mismatches {
        println!("{m}");
    }
    assert!(mismatches.is_empty(), "{} disagreements", mismatches.len());
}
