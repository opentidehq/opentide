//! `opentide_core::difflib` returns what Python's `difflib` returns, bit for bit,
//! on every case of `tests/data/difflib_cases.json`, which
//! `scripts/build/gen_difflib_cases.py` records from Python (CI's engine job
//! fails when the file is stale).

#![expect(
    clippy::expect_used,
    reason = "helpers outside #[test] read a fixture the generator wrote; a malformed one should panic"
)]

use opentide_core::difflib::{Match, SequenceMatcher, get_close_matches};
use serde_json::Value;

fn text(value: &Value, key: &str) -> String {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string: {value}"))
        .to_owned()
}

/// A float the generator wrote as Python's `repr`; Rust's parser rounds
/// correctly, so this is the same `f64`.
fn float(value: &Value, key: &str) -> f64 {
    text(value, key)
        .parse()
        .unwrap_or_else(|err| panic!("{key}: {err}"))
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("not an array: {value}"))
        .iter()
        .map(|v| v.as_str().expect("a string").to_owned())
        .collect()
}

#[test]
fn every_case_matches_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/difflib_cases.json");
    let data: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("the fixture")).expect("JSON");
    let pools = &data["pools"];
    let cases = data["cases"].as_array().expect("cases");
    assert!(cases.len() >= 3000, "only {} cases", cases.len());

    let mut failures = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let word = text(case, "word");
        let possibilities = match case.get("pool") {
            Some(pool) => strings(&pools[pool.as_str().expect("pool name")]),
            None => strings(&case["possibilities"]),
        };
        let n = usize::try_from(case["n"].as_u64().expect("n")).expect("n fits");
        let cutoff = float(case, "cutoff");
        let expected = strings(&case["expected"]);
        let got = get_close_matches(&word, possibilities.iter().map(String::as_str), n, cutoff);
        if got != expected {
            failures.push(format!(
                "case {index} get_close_matches({word:?}, n={n}, cutoff={cutoff}): got {got:?}, Python {expected:?}"
            ));
        }

        let pair = &case["pair"];
        let (a, b) = (text(pair, "a"), text(pair, "b"));
        let junk = pair["junk"].as_str().map(str::to_owned);
        let isjunk = |c: char| junk.as_deref().is_some_and(|j| j.contains(c));
        let isjunk_ref: Option<&dyn Fn(char) -> bool> =
            if junk.is_some() { Some(&isjunk) } else { None };
        let autojunk = pair["autojunk"].as_bool().expect("autojunk");
        let mut s = SequenceMatcher::with_options(&a, &b, isjunk_ref, autojunk);
        let blocks: Vec<Match> = pair["matching_blocks"]
            .as_array()
            .expect("blocks")
            .iter()
            .map(|m| {
                let at = |i: usize| usize::try_from(m[i].as_u64().expect("index")).expect("fits");
                Match {
                    a: at(0),
                    b: at(1),
                    size: at(2),
                }
            })
            .collect();
        if s.get_matching_blocks() != blocks.as_slice() {
            failures.push(format!(
                "case {index} matching blocks of ({a:?}, {b:?}): got {:?}, Python {blocks:?}",
                s.get_matching_blocks()
            ));
        }
        for (name, got, want) in [
            ("ratio", s.ratio(), float(pair, "ratio")),
            ("quick_ratio", s.quick_ratio(), float(pair, "quick_ratio")),
            (
                "real_quick_ratio",
                s.real_quick_ratio(),
                float(pair, "real_quick_ratio"),
            ),
        ] {
            if got.to_bits() != want.to_bits() {
                failures.push(format!(
                    "case {index} {name}({a:?}, {b:?}): got {got:?}, Python {want:?}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ from Python:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
