//! Every input the `from_node` fuzz target saved (`fuzz/regressions/from_node/`)
//! and its seeds (`fuzz/seeds/from_node/`), run on stable Rust as
//! `fuzz/src/lib.rs::from_node` runs them (a copy of it, below): the YAML
//! loader, the conversion into every model, each error's span, and the round
//! trip of what converts. A crash the fuzzer finds is saved there and stays
//! fixed (`fuzz/README.md`).

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use opentide_schema::from_node::from_document;
use opentide_schema::node::{self, Document};
use opentide_schema::objects::{ObjectiveV1_0, ThreatVectorV1_0};
use opentide_schema::sample::{SampleV1_0, SampleV1_1};

/// The fuzzer's `-timeout` in CI is 10 s per input; a debug build gets more.
const BUDGET: Duration = Duration::from_secs(30);

fn convert<T>(document: &Document)
where
    T: opentide_schema::FromNode + serde::Serialize + PartialEq + std::fmt::Debug,
{
    match from_document::<T>(document) {
        Ok(value) => {
            let yaml = node::to_yaml(&value).expect("a converted model writes");
            let again = node::load(&yaml).expect("what to_yaml writes reads back");
            let back: T = from_document(&again).expect("what to_yaml writes converts");
            assert_eq!(back, value, "{yaml}");
        }
        Err(errors) => {
            assert!(!errors.is_empty());
            let lines = document.source().split(['\r', '\n']).count();
            for error in &errors {
                assert!(!error.message.is_empty(), "{error:?}");
                if let Some(span) = &error.span {
                    assert!(span.line >= 1 && span.line <= lines + 1, "{error:?}");
                    assert!(
                        span.column >= 1 && span.end_column >= span.column,
                        "{error:?}"
                    );
                }
            }
        }
    }
}

fn from_node(data: &[u8]) {
    let Ok(document) = node::load_bytes(data) else {
        return;
    };
    convert::<SampleV1_0>(&document);
    convert::<SampleV1_1>(&document);
    convert::<opentide_schema::objects::RuleV1_0>(&document);
    convert::<opentide_schema::objects::RuleV1_1>(&document);
    convert::<ThreatVectorV1_0>(&document);
    convert::<ObjectiveV1_0>(&document);
}

fn inputs(directory: &str) -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz")
        .join(directory);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name != ".gitattributes")
        })
        .collect();
    paths.sort();
    paths
}

#[test]
fn every_seed_and_saved_input_runs_clean() {
    let seeds = inputs("seeds/from_node");
    assert!(seeds.len() > 100, "{} seeds", seeds.len());
    for path in seeds.iter().chain(&inputs("regressions/from_node")) {
        let data = std::fs::read(path).unwrap();
        let started = Instant::now();
        from_node(&data);
        assert!(
            started.elapsed() < BUDGET,
            "{} took {:?}",
            path.display(),
            started.elapsed()
        );
    }
}

/// A billion laughs: aliases nested so the tree expands to 2^40 values. The
/// loader shares aliased nodes and the conversion stops at its budget.
#[test]
fn nested_aliases_neither_hang_nor_exhaust_memory() {
    let mut text = String::from("a0: &a0 [x, x]\n");
    for level in 1..40 {
        let previous = level - 1;
        text.push_str(&format!(
            "a{level}: &a{level} [*a{previous}, *a{previous}]\n"
        ));
    }
    text.push_str("tags: *a39\nexamples: [*a39, *a39]\n");
    let started = Instant::now();
    from_node(text.as_bytes());
    assert!(started.elapsed() < BUDGET, "{:?}", started.elapsed());
}
