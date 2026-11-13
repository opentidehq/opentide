//! Measurement over Exabeam's published correlation rules
//! (ExabeamLabs/new-scale-content-hub, `Correlation-Rules/**/*.json`). Its
//! README forbids redistribution, so nothing of it is in this repository: the
//! test is ignored and reads a local checkout.
//!
//! ```text
//! EXABEAM_CONTENT_HUB=../new-scale-content-hub \
//!   EXABEAM_RESULTS=/tmp/exabeam-engine.json \
//!   cargo test -p opentide-exabeam --test content_hub -- --ignored --nocapture
//! ```
//!
//! It writes every rule's findings (`EXABEAM_RESULTS`, for a comparison with
//! the reference checker) and prints the totals `docs/engine/EXABEAM.md` records.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_exabeam::{Profile, check};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn rule_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rule_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

#[test]
#[ignore = "needs a local new-scale-content-hub checkout (EXABEAM_CONTENT_HUB)"]
fn published_correlation_rules() {
    let Ok(root) = std::env::var("EXABEAM_CONTENT_HUB") else {
        eprintln!("EXABEAM_CONTENT_HUB is unset");
        return;
    };
    let root = PathBuf::from(root);
    let mut paths = Vec::new();
    rule_files(&root.join("Correlation-Rules"), &mut paths);
    paths.sort();
    let mut results = Vec::new();
    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut with_errors: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut tree_sitter_errors = 0;
    let mut token_disagreements = 0;
    let spec = opentide_highlight::HighlightSpec::load().unwrap();
    for path in &paths {
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let rule = doc
            .get("ruleDefinitions")
            .and_then(|d| d.get(0))
            .unwrap_or(&doc);
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let group = if relative.contains("exabeam_new_scale_correlation_rule_json-2025") {
            "converted"
        } else {
            "native"
        };
        for sequence in rule["sequencesConfig"]["sequences"].as_array().unwrap() {
            let query = sequence["query"].as_str().unwrap();
            let checked = check(query, Profile::Rule);
            let errors = checked
                .findings
                .iter()
                .filter(|f| !opentide_exabeam::is_warning(f.code))
                .count();
            let entry = with_errors.entry(group).or_default();
            entry.0 += 1;
            entry.1 += usize::from(errors > 0);
            for f in &checked.findings {
                *totals.entry(f.code.to_string()).or_default() += 1;
            }
            let tree = opentide_syntax::parse(opentide_core::LanguageId::Exabeam, query).unwrap();
            // A query the verdict parser finds no error in must parse, and
            // highlight as the verdict parser tokenizes it.
            let clean = errors == 0;
            if tree.root_node().has_error() && clean {
                tree_sitter_errors += 1;
            }
            let highlighted: Vec<(usize, usize, String)> =
                opentide_exabeam::highlight(&spec, query)
                    .into_iter()
                    .map(|t| (t.span.start, t.span.end, t.capture))
                    .collect();
            let verdict: Vec<(usize, usize, String)> = checked
                .tokens
                .iter()
                .map(|t| (t.start, t.end, t.capture.to_string()))
                .collect();
            let tokens_agree = highlighted == verdict;
            if !tokens_agree && clean {
                token_disagreements += 1;
            }
            results.push(serde_json::json!({
                "path": relative,
                "findings": checked.findings.iter().map(|f| serde_json::json!({
                    "code": f.code, "start": f.start, "end": f.end, "message": f.message,
                })).collect::<Vec<_>>(),
                "tree_sitter_error": tree.root_node().has_error(),
                "tokens_agree": tokens_agree,
                "tokens": verdict,
            }));
        }
    }
    eprintln!("rules: {}", paths.len());
    eprintln!("queries with errors (group: queries, with errors): {with_errors:?}");
    eprintln!("findings by code: {totals:#?}");
    eprintln!("error-free queries with a tree-sitter error: {tree_sitter_errors}");
    eprintln!("error-free queries whose highlighting differs: {token_disagreements}");
    if let Ok(out) = std::env::var("EXABEAM_RESULTS") {
        std::fs::write(out, serde_json::to_string(&results).unwrap()).unwrap();
    }
}
