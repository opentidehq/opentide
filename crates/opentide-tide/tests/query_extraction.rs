//! Every Tide object under `crates/testdata/`: the queries the engine extracts are the
//! ones YAML loads at the paths opentide models, with the same text.
//!
//! The expected side reads each file with the workspace's YAML reader
//! (`opentide_core::node`, as `validate` does) and follows the rules
//! `scripts/engine/oracles/oracle.py` (`embedded`, `elastic_embedded`) uses to feed
//! the reference parsers, so the oracles check the text the engine checks.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::LanguageId;
use opentide_core::node::{self, Node, Value};
use opentide_schema::objects::platform::google_secops::yaral::section_header_line;
use opentide_tide::{elastic_query_language, extract_injections, hunt_query_language};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

fn text(value: Option<&Arc<Node>>) -> Option<&str> {
    value.and_then(|v| v.value.as_str())
}

fn sequence(value: Option<&Arc<Node>>) -> Option<&[Arc<Node>]> {
    match &value?.value {
        Value::Seq(items) => Some(items),
        _ => None,
    }
}

/// The queries a YAML loader finds, as `(path, language, platform, text)`.
fn expected(doc: &Node, source: &str) -> BTreeSet<Query> {
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
        ("crowdstrike", &["query"][..], LanguageId::Cql),
        ("graylog", &["query"][..], LanguageId::Lucene),
    ] {
        let block = configurations.and_then(|c| c.get(platform));
        for field in fields {
            if let Some(value) = text(block.and_then(|b| b.get(field))) {
                add(
                    format!("configurations.{platform}.{field}"),
                    language,
                    platform,
                    value,
                );
            }
        }
    }
    // A YaraSignature written out in the block; an alias is not analysed
    // (`yara_signature_alias`), though a loader resolves it.
    let alias = source.contains("signature: *");
    for platform in ["harfanglab", "bitdefender"] {
        let yara = configurations
            .and_then(|c| c.get(platform))
            .and_then(|b| b.get("yara"));
        if let Some(value) = text(yara.and_then(|y| y.get("signature")))
            && !alias
        {
            add(
                format!("configurations.{platform}.yara.signature"),
                LanguageId::Yara,
                platform,
                value,
            );
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
        if rule_type == Some("threat_match")
            && let (Some(language), Some(value)) = (
                elastic_query_language(
                    Some("threat_match"),
                    text(threat.and_then(|t| t.get("language"))),
                ),
                text(threat.and_then(|t| t.get("query"))),
            )
        {
            add(
                "configurations.elastic.threat.query".into(),
                language,
                "elastic",
                value,
            );
        }
    }
    if let Some(sysdig) = configurations.and_then(|c| c.get("sysdig")) {
        for field in ["condition", "output"] {
            if let Some(value) = text(sysdig.get(field)) {
                add(
                    format!("configurations.sysdig.{field}"),
                    LanguageId::Falco,
                    "sysdig",
                    value,
                );
            }
        }
        let macros = sequence(sysdig.get("macros"));
        for (n, m) in macros.into_iter().flatten().enumerate() {
            if let Some(value) = text(m.get("condition")) {
                add(
                    format!("configurations.sysdig.macros.{n}.condition"),
                    LanguageId::Falco,
                    "sysdig",
                    value,
                );
            }
        }
    }
    // A Google SecOps block's text sections, each its own injection (the
    // analysis checks them together, as the rule deploy assembles). A block
    // with no `events` text, or a section text holding a label or a header,
    // is not a rule: its sections are not queries.
    let sections = ["setup", "events", "outcome", "condition", "export"];
    let checked = |secops: &Arc<Node>| {
        text(secops.get("events")).is_some_and(|events| !events.trim().is_empty())
            && sections.iter().all(|field| {
                text(secops.get(field)).is_none_or(|value| section_header_line(value).is_none())
            })
    };
    if let Some(secops) = configurations
        .and_then(|c| c.get("google_secops"))
        .filter(|secops| checked(secops))
    {
        for field in sections {
            if let Some(value) = text(secops.get(field)) {
                add(
                    format!("configurations.google_secops.{field}"),
                    LanguageId::Yaral,
                    "google_secops",
                    value,
                );
            }
        }
    }
    // An Exabeam block's sequence filters, each its own injection.
    let exabeam = configurations.and_then(|c| c.get("exabeam"));
    let exabeam_sequences = sequence(exabeam.and_then(|b| b.get("sequences")));
    for (n, item) in exabeam_sequences.into_iter().flatten().enumerate() {
        if let Some(value) = text(item.get("query")) {
            add(
                format!("configurations.exabeam.sequences.{n}.query"),
                LanguageId::Exabeam,
                "exabeam",
                value,
            );
        }
    }
    let searches = sequence(
        doc.get("response")
            .and_then(|r| r.get("procedure"))
            .and_then(|p| p.get("searches")),
    );
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
    yaml_files(&repo_root().join("crates/testdata"), &mut files);
    files.sort();
    let mut checked = 0;
    let mut hunts = 0;
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap();
        let Ok(document) = node::load(&source) else {
            continue;
        };
        let Some(doc) = document.root() else {
            continue;
        };
        let want = expected(doc, &source);
        // A HarfangLab decomposed YARA rule is assembled from several fields,
        // which no loader does: tests/yara.rs checks it.
        let got: BTreeSet<Query> = extract_injections(&source)
            .into_iter()
            .filter(|q| q.parts.is_empty())
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
    assert!(
        checked >= 20,
        "only {checked} queries under crates/testdata/"
    );
    assert!(hunts >= 3, "only {hunts} hunts under crates/testdata/");
}
