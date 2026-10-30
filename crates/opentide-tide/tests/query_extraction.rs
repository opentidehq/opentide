//! Every Tide object under `testdata/`: the queries the engine extracts are the
//! ones YAML loads at the paths opentide models, with the same text.
//!
//! The expected side reads each file with `serde_yaml` and follows the rules
//! `scripts/oracles/oracle.py` (`embedded`, `elastic_embedded`) uses to feed
//! the reference parsers, so the oracles check the text the engine checks.

use opentide_core::LanguageId;
use opentide_tide::{elastic_query_language, extract_injections, hunt_query_language};
use serde_yaml::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            yaml_files(&path, out);
        } else if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("yaml" | "yml")
        ) {
            out.push(path);
        }
    }
}

/// `(path, language, platform, text)`.
type Query = (String, &'static str, String, String);

fn text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

/// The queries a YAML loader finds, as `(path, language, platform, text)`.
fn expected(doc: &Value) -> BTreeSet<Query> {
    let mut out = BTreeSet::new();
    let mut add = |path: String, language: LanguageId, platform: &str, value: &str| {
        let value = value.trim_matches(['\n', '\r']);
        if !value.trim().is_empty() {
            out.insert((
                path,
                language.as_str(),
                platform.to_string(),
                value.to_string(),
            ));
        }
    };
    let configurations = doc.get("configurations");
    for (platform, fields, language) in [
        ("sentinel", &["query"][..], LanguageId::Kql),
        ("defender_for_endpoint", &["query"][..], LanguageId::Kql),
        ("splunk", &["query", "search"][..], LanguageId::Spl),
        ("carbon_black_cloud", &["query"][..], LanguageId::Lucene),
    ] {
        let block = configurations.and_then(|c| c.get(platform));
        for field in fields {
            if let Some(value) = text(block.and_then(|b| b.get(*field))) {
                add(
                    format!("configurations.{platform}.{field}"),
                    language,
                    platform,
                    value,
                );
            }
        }
    }
    if let Some(elastic) = configurations.and_then(|c| c.get("elastic")) {
        let rule_type = text(elastic.get("type"));
        if let (Some(language), Some(value)) = (
            elastic_query_language(rule_type, text(elastic.get("language"))),
            text(elastic.get("query")),
        ) {
            add(
                "configurations.elastic.query".into(),
                language,
                "elastic",
                value,
            );
        }
        let threat = elastic.get("threat");
        if rule_type == Some("threat_match") {
            if let (Some(language), Some(value)) = (
                elastic_query_language(
                    Some("threat_match"),
                    text(threat.and_then(|t| t.get("language"))),
                ),
                text(threat.and_then(|t| t.get("query"))),
            ) {
                add(
                    "configurations.elastic.threat.query".into(),
                    language,
                    "elastic",
                    value,
                );
            }
        }
    }
    let searches = doc
        .get("response")
        .and_then(|r| r.get("procedure"))
        .and_then(|p| p.get("searches"))
        .and_then(Value::as_sequence);
    for (n, search) in searches.into_iter().flatten().enumerate() {
        let (Some(system), Some(value)) = (text(search.get("system")), text(search.get("query")))
        else {
            continue;
        };
        if let Some(language) = hunt_query_language(system, text(search.get("language"))) {
            add(
                format!("response.procedure.searches.{n}.query"),
                language,
                system,
                value,
            );
        }
    }
    out
}

#[test]
fn every_testdata_query_is_extracted_as_yaml_loads_it() {
    let mut files = Vec::new();
    yaml_files(&repo_root().join("testdata"), &mut files);
    files.sort();
    let mut checked = 0;
    let mut hunts = 0;
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap();
        let Ok(doc) = serde_yaml::from_str::<Value>(&source) else {
            continue;
        };
        let want = expected(&doc);
        let got: BTreeSet<Query> = extract_injections(&source)
            .into_iter()
            .map(|q| {
                (
                    q.field_path.join("."),
                    q.language.as_str(),
                    q.platform,
                    q.inner,
                )
            })
            .collect();
        assert_eq!(got, want, "{}", path.display());
        checked += want.len();
        hunts += want.iter().filter(|q| q.0.starts_with("response.")).count();
    }
    assert!(checked >= 20, "only {checked} queries under testdata/");
    assert!(hunts >= 3, "only {hunts} hunts under testdata/");
}
