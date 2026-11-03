//! The Falco default rules (falcosecurity/rules and the falcosecurity/plugins
//! rules files), each condition unmodified, plus a twin with one injected
//! fault.
//!
//! Sources and licence: `testdata/conformance/external/SOURCES.md`. The
//! conditions are written by `scripts/sync_falco_catalog.py --corpus`, one
//! directory per event source. Every public condition must parse and come out
//! clean: no error and no warning, with the default macros and lists the
//! engine bundles. Every broken twin must report `falco_parse_error`.

use opentide_analysis::{LanguageId, QueryRequest, Severity, analyze_query, codes};
use opentide_falco::{Context, analyze_with};
use std::fs;
use std::path::PathBuf;

fn corpus() -> Vec<(String, String, String, String)> {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/conformance/external/falco");
    let mut out = Vec::new();
    for dir in fs::read_dir(&root).unwrap() {
        let dir = dir.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        let source = dir.file_name().unwrap().to_string_lossy().into_owned();
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".falco") || name.contains(".broken.") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            let broken = fs::read_to_string(path.with_extension("broken.falco"))
                .unwrap_or_else(|_| panic!("{source}/{name} has no broken twin"));
            out.push((source.clone(), name, text, broken));
        }
    }
    out.sort();
    out
}

#[test]
fn every_public_falco_condition_is_clean() {
    let corpus = corpus();
    assert!(
        corpus.len() >= 200,
        "expected the Falco default rules, got {}",
        corpus.len()
    );
    for source in [
        "syscall",
        "k8s_audit",
        "aws_cloudtrail",
        "okta",
        "github",
        "gcp_auditlog",
    ] {
        assert!(
            corpus.iter().any(|(s, ..)| s == source),
            "no public {source} rule in the corpus"
        );
    }
    for (source, name, text, _) in &corpus {
        let ctx = Context {
            source: Some(source.clone()),
            append: Some(false),
            ..Context::default()
        };
        let found = analyze_with(text, &ctx).diagnostics;
        assert!(
            found.is_empty(),
            "{source}/{name}: {:?}",
            found
                .iter()
                .map(|d| (d.code.as_str(), d.message.as_str()))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn every_broken_twin_is_a_parse_error() {
    for (source, name, _, broken) in corpus() {
        let ctx = Context {
            source: Some(source.clone()),
            ..Context::default()
        };
        let found = analyze_with(&broken, &ctx).diagnostics;
        assert!(
            found
                .iter()
                .any(|d| d.code == codes::FALCO_PARSE_ERROR && d.severity == Severity::Error),
            "{source}/{name} broken twin: {found:?}"
        );
    }
}

/// A raw `.falco` file and `analyze_query` agree: the default context is
/// the `syscall` source.
#[test]
fn raw_falco_queries_use_the_syscall_source() {
    let request = |text: &str| QueryRequest {
        language: LanguageId::Falco,
        platform: Some("sysdig".into()),
        stack: None,
        text: text.into(),
    };
    assert!(analyze_query(&request("spawned_process and proc.name = bash")).is_empty());
    let found = analyze_query(&request("ka.verb = create"));
    let found: Vec<&str> = found.iter().map(|d| d.code.as_str()).collect();
    // Not a field of `syscall`: an error, as Falco refuses it, so the event
    // types are not judged (Falco stops at the error too).
    assert_eq!(found, [codes::FALCO_UNKNOWN_FIELD]);
}
