//! libsinsp's own parser tests (`crates/testdata/conformance/libsinsp/parser.json`,
//! ported from falcosecurity/libs `filter_parser.ut.cpp` by
//! `scripts/engine/sync_libsinsp_conformance.py`): every accepted input parses, every
//! rejected one fails with libs' message where the test names one, and the
//! AST prints as libs prints it.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_falco::parser::parse;
use serde_json::Value;
use std::path::PathBuf;

fn fixtures() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/conformance/libsinsp/parser.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["fixtures"].as_array().unwrap().clone()
}

/// libs' `test_accept` also parses each input padded with spaces, then with
/// every space a line break, then with every line break a tab.
fn variants(input: &str) -> Vec<String> {
    let padded = format!(" {input} ");
    let lines = padded.replace(' ', "\n");
    let tabs = lines.replace('\n', "\t");
    vec![input.to_string(), padded, lines, tabs]
}

#[test]
fn every_libsinsp_parser_verdict_agrees() {
    let all = fixtures();
    assert!(all.len() >= 570, "{}", all.len());
    let mut failures = Vec::new();
    for fx in &all {
        let input = fx["input"].as_str().unwrap();
        let at = format!("{}:{}", fx["test"].as_str().unwrap(), fx["line"]);
        match fx["verdict"].as_str().unwrap() {
            "accept" => {
                let inputs = if fx["variants"].as_bool().unwrap() {
                    variants(input)
                } else {
                    vec![input.to_string()]
                };
                for text in inputs {
                    match parse(&text) {
                        Ok(ast) => {
                            if let Some(expected) = fx.get("ast").and_then(Value::as_str)
                                && text == input
                                && ast.as_string() != expected
                            {
                                failures.push(format!(
                                    "{at}: {input:?} prints {:?}, libs {expected:?}",
                                    ast.as_string()
                                ));
                            }
                        }
                        Err(e) => failures.push(format!("{at}: rejects {text:?}: {}", e.message)),
                    }
                }
            }
            _ => match parse(input) {
                Ok(ast) => failures.push(format!("{at}: accepts {input:?} as {}", ast.as_string())),
                Err(e) => {
                    if let Some(msg) = fx.get("message").and_then(Value::as_str)
                        && e.message != msg
                    {
                        failures.push(format!("{at}: {input:?}: {:?}, libs {msg:?}", e.message));
                    }
                }
            },
        }
    }
    assert!(
        failures.is_empty(),
        "{} disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn the_recursion_limit_matches_libsinsp() {
    // filter_parser.ut.cpp recursion_depth_limit (not a literal, so not in the file).
    let err = parse(&"(".repeat(100_000)).unwrap_err();
    assert_eq!(err.message, "exceeded max depth limit of 100");
    assert!(parse("((((((((((a))))))))))").is_ok());
}
