//! libsinsp's own compiler tests (`testdata/conformance/libsinsp/compiler.json`,
//! ported from falcosecurity/libs `filter_compiler.ut.cpp`): every filter libs
//! compiles compiles here with libs' warning count, and every filter libs
//! refuses gets an error.
//!
//! The tests' mock fields stand for real ones of the same type: `c.buffer`
//! (`PT_BYTEBUF`) is `evt.buffer`; `c.true`, `c.false`, `c.doublequote`, and
//! `c.singlequote` (`PT_CHARBUF`, no flags) are `fd.name`.

use opentide_falco::Catalog;
use opentide_falco::compile::{Compiler, Level};
use opentide_falco::parser::parse;
use serde_json::Value;
use std::path::PathBuf;

const LIBSINSP_WARNINGS: &[&str] = &[
    "falco_regex_simple",
    "falco_field_as_value",
    "falco_transformer_as_value",
];

fn fixtures() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance/libsinsp/compiler.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["fixtures"].as_array().unwrap().clone()
}

fn unmock(filter: &str) -> String {
    let mut out = filter.replace("c.buffer", "evt.buffer");
    for f in ["c.true", "c.false", "c.doublequote", "c.singlequote"] {
        out = out.replace(f, "fd.name");
    }
    out
}

#[test]
fn every_libsinsp_compiler_verdict_agrees() {
    let all = fixtures();
    assert!(all.len() >= 320, "{}", all.len());
    let catalog = Catalog::cached();
    let mut failures = Vec::new();
    for fx in &all {
        let filter = unmock(fx["filter"].as_str().unwrap());
        let at = format!("{}:{}", fx["test"].as_str().unwrap(), fx["line"]);
        let expect_fail = fx["fail"].as_bool().unwrap();
        let ast = match parse(&filter) {
            Ok(ast) => ast,
            Err(e) => {
                if !expect_fail {
                    failures.push(format!("{at}: {filter:?} does not parse: {}", e.message));
                }
                continue;
            }
        };
        let mut compiler = Compiler::new(catalog, "syscall");
        compiler.condition(&ast);
        let fails = compiler
            .findings
            .iter()
            .any(|f| f.level == Level::Error || f.code == "falco_unknown_field");
        let warnings = compiler
            .findings
            .iter()
            .filter(|f| LIBSINSP_WARNINGS.contains(&f.code))
            .count();
        if fails != expect_fail {
            failures.push(format!(
                "{at}: {filter:?}: libs {}, engine {} {:?}",
                if expect_fail { "fails" } else { "compiles" },
                if fails { "fails" } else { "compiles" },
                compiler
                    .findings
                    .iter()
                    .map(|f| (f.code, f.message.as_str()))
                    .collect::<Vec<_>>()
            ));
        } else if !expect_fail && warnings as u64 != fx["warnings"].as_u64().unwrap() {
            failures.push(format!(
                "{at}: {filter:?}: libs {} warnings, engine {warnings} {:?}",
                fx["warnings"],
                compiler.findings.iter().map(|f| f.code).collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
