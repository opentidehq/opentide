//! Opt-in sweep over Elastic's public detection rules.
//!
//! Set `OPENTIDE_DETECTION_RULES` to an `elastic/detection-rules` checkout
//! and run `cargo test -p opentide-analysis --test elastic_detection_rules`.
//! The rules are Elastic License 2.0, so they are read from the checkout and
//! never copied into this repository.
//!
//! Every rule there passes Elasticsearch's parser, so any *error* from the
//! ES|QL, EQL, kuery, or Lucene engine is an engine bug. Warnings are
//! reported as a tally only: they are advisories about real rules. List them
//! with `OPENTIDE_SWEEP_SHOW=eql_literal_wildcard,kuery_escape`.

use opentide_core::{Diagnostic, LanguageId, Severity};
use opentide_tide::elastic_query_language;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn rule_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rule_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "toml") {
            out.push(path);
        }
    }
}

/// A rule's `metadata.min_stack_version` (`"9.5.0"`) as the stack its ES|QL
/// must run on, so a rule built for 9.5 is not checked against 8.19.
fn min_stack(doc: &toml::Table) -> Option<opentide_esql::StackTarget> {
    let version = doc.get("metadata")?.get("min_stack_version")?.as_str()?;
    let mut parts = version.split('.');
    let major_minor = format!("{}.{}", parts.next()?, parts.next()?);
    opentide_esql::StackTarget::parse(&major_minor)
}

fn analyze(
    language: LanguageId,
    query: &str,
    stack: Option<opentide_esql::StackTarget>,
) -> Vec<Diagnostic> {
    match language {
        LanguageId::Esql => opentide_esql::analyze_for(query, stack).diagnostics,
        LanguageId::Eql => opentide_eql::analyze(query).diagnostics,
        LanguageId::Kuery => opentide_kuery::analyze(query).diagnostics,
        LanguageId::Lucene => opentide_lucene::analyze(query).diagnostics,
        _ => Vec::new(),
    }
}

#[test]
fn every_public_elastic_rule_is_free_of_engine_errors() {
    let Some(root) = std::env::var_os("OPENTIDE_DETECTION_RULES") else {
        eprintln!("OPENTIDE_DETECTION_RULES is not set; skipping the detection-rules sweep");
        return;
    };
    let root = PathBuf::from(root);
    let mut files = Vec::new();
    for dir in ["rules", "rules_building_block", "hunting"] {
        rule_files(&root.join(dir), &mut files);
    }
    files.sort();
    let mut checked: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut warnings: BTreeMap<String, usize> = BTreeMap::new();
    let mut errors = Vec::new();
    let show: Vec<String> = std::env::var("OPENTIDE_SWEEP_SHOW")
        .map(|v| v.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    for path in &files {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(doc) = text.parse::<toml::Table>() else {
            continue;
        };
        let mut queries = Vec::new();
        if let Some(hunt) = doc.get("hunt").and_then(|h| h.as_table()) {
            // Hunts list their languages; analyse those with exactly one.
            let languages: Vec<&str> = hunt
                .get("language")
                .and_then(|l| l.as_array())
                .map(|l| l.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let language = match languages.as_slice() {
                ["ES|QL"] => Some(LanguageId::Esql),
                ["EQL"] => Some(LanguageId::Eql),
                _ => None,
            };
            let hunt_queries = hunt.get("query").and_then(|q| q.as_array());
            if let (Some(language), Some(list)) = (language, hunt_queries) {
                queries.extend(
                    list.iter()
                        .filter_map(|q| q.as_str())
                        .map(|q| (language, q)),
                );
            }
        }
        let Some(rule) = doc.get("rule").and_then(|r| r.as_table()) else {
            for (language, query) in queries {
                *checked.entry(language.as_str()).or_default() += 1;
                let query = query.trim();
                for d in analyze(language, query, min_stack(&doc)) {
                    if d.severity == Severity::Error {
                        errors.push(format!(
                            "{}: {} {}:{} {}",
                            path.strip_prefix(&root).unwrap_or(path).display(),
                            d.code,
                            d.range.start.line + 1,
                            d.range.start.character + 1,
                            d.message
                        ));
                    }
                }
            }
            continue;
        };
        let get = |key: &str| rule.get(key).and_then(|v| v.as_str());
        if let (Some(query), Some(language)) = (
            get("query"),
            elastic_query_language(get("type"), get("language")),
        ) {
            queries.push((language, query));
        }
        if let (Some(query), Some(language)) = (
            get("threat_query"),
            elastic_query_language(Some("threat_match"), get("threat_language")),
        ) {
            queries.push((language, query));
        }
        for (language, query) in queries {
            *checked.entry(language.as_str()).or_default() += 1;
            let query = query.trim_end();
            for d in analyze(language, query, min_stack(&doc)) {
                if show.contains(&d.code) {
                    let line = query.lines().nth(d.range.start.line as usize).unwrap_or("");
                    eprintln!(
                        "{} {}: {} | {}",
                        d.code,
                        path.strip_prefix(&root).unwrap_or(path).display(),
                        d.message,
                        line.trim()
                    );
                }
                if d.severity == Severity::Error {
                    errors.push(format!(
                        "{}: {} {}:{} {}",
                        path.strip_prefix(&root).unwrap_or(path).display(),
                        d.code,
                        d.range.start.line + 1,
                        d.range.start.character + 1,
                        d.message
                    ));
                } else {
                    *warnings.entry(d.code).or_default() += 1;
                }
            }
        }
    }
    eprintln!("checked {checked:?}; non-error diagnostics {warnings:?}");
    assert!(
        checked.values().sum::<usize>() > 1000,
        "expected the detection-rules corpus under {}",
        root.display()
    );
    assert!(
        errors.is_empty(),
        "{} engine errors on public rules:\n{}",
        errors.len(),
        errors.join("\n")
    );
}
