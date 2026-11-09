//! Public CQL queries from CrowdStrike/logscale-community-content, each
//! unmodified, plus a twin with one injected fault.
//!
//! Sources and licence: `crates/testdata/conformance/external/SOURCES.md`. Only the
//! Unlicense parts of the repository are used. `cql/FAULTS.toml` lists every
//! public query with the fault injected into its `.broken.cql` twin and the
//! code that twin must report. Every public query must come out clean: no
//! finding of any severity, as a raw query and through `analyze_query`.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_analysis::{Diagnostic, LanguageId, QueryRequest, analyze_query, codes};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/conformance/external/cql")
}

/// Every fault kind the twins must cover, with the code it produces.
const FAULTS: &[(&str, &str)] = &[
    ("unbalanced-paren", codes::CQL_PARSE_ERROR),
    ("unbalanced-brace", codes::CQL_PARSE_ERROR),
    ("dangling-operator", codes::CQL_PARSE_ERROR),
    ("url-pattern-comment", codes::CQL_PARSE_ERROR),
    ("unknown-function", codes::CQL_UNKNOWN_FUNCTION),
    ("unknown-parameter", codes::CQL_UNKNOWN_PARAMETER),
    ("second-unnamed-argument", codes::CQL_UNNAMED_ARGUMENT),
    ("duplicate-parameter", codes::CQL_DUPLICATE_PARAMETER),
    ("missing-parameter", codes::CQL_MISSING_PARAMETER),
    ("bad-enum-value", codes::CQL_PARAMETER_VALUE),
    ("bad-regex-flag", codes::CQL_REGEX_FLAG),
    (
        "free-text-after-aggregate",
        codes::CQL_FREE_TEXT_AFTER_AGGREGATE,
    ),
    ("assignment-with-as", codes::CQL_ASSIGNMENT_AS),
    ("link-outside-correlate", codes::CQL_LINK_OUTSIDE_CORRELATE),
];

struct Entry {
    file: String,
    fault: String,
    code: String,
}

fn manifest() -> Vec<Entry> {
    let text = fs::read_to_string(root().join("FAULTS.toml")).unwrap();
    let doc: toml::Table = text.parse().unwrap();
    let field = |q: &toml::Value, key: &str| -> String {
        q.get(key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("FAULTS.toml entry without `{key}`: {q}"))
            .to_owned()
    };
    doc["query"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| Entry {
            file: field(q, "file"),
            fault: field(q, "fault"),
            code: field(q, "code"),
        })
        .collect()
}

/// Every `.cql` file under `cql/`, as a path relative to it.
fn files(dir: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, out);
        } else if path.extension().is_some_and(|e| e == "cql") {
            let rel = path.strip_prefix(root()).unwrap();
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn twin(file: &str) -> String {
    file.strip_suffix(".cql")
        .map(|stem| format!("{stem}.broken.cql"))
        .unwrap()
}

fn summary(found: &[Diagnostic]) -> Vec<(&str, &str)> {
    found
        .iter()
        .map(|d| (d.code.as_str(), d.message.as_str()))
        .collect()
}

/// The manifest names every file in the directory, each public query has a
/// twin, every listed fault kind is known with the right code, and none is
/// missing: the harness cannot pass on an empty or shrunken set.
#[test]
fn manifest_covers_the_corpus() {
    let manifest = manifest();
    assert!(
        manifest.len() >= 30,
        "expected at least 30 public CQL queries, got {}",
        manifest.len()
    );
    let mut on_disk = Vec::new();
    files(&root(), &mut on_disk);
    let on_disk: BTreeSet<String> = on_disk.into_iter().collect();
    let mut listed = BTreeSet::new();
    for entry in &manifest {
        assert!(
            !entry.file.contains(".broken."),
            "{}: list the public query",
            entry.file
        );
        assert!(listed.insert(entry.file.clone()), "{} twice", entry.file);
        assert!(listed.insert(twin(&entry.file)));
        let (_, code) = FAULTS
            .iter()
            .find(|(kind, _)| *kind == entry.fault)
            .unwrap_or_else(|| panic!("{}: unknown fault kind {}", entry.file, entry.fault));
        assert_eq!(&entry.code, code, "{}: {}", entry.file, entry.fault);
    }
    assert_eq!(listed, on_disk, "FAULTS.toml and the files disagree");
    for (kind, _) in FAULTS {
        assert!(
            manifest.iter().any(|e| e.fault == *kind),
            "no twin injects {kind}"
        );
    }
}

#[test]
fn every_public_cql_query_is_clean() {
    for entry in manifest() {
        let text = fs::read_to_string(root().join(&entry.file)).unwrap();
        let found = opentide_cql::analyze(&text).diagnostics;
        assert!(found.is_empty(), "{}: {:?}", entry.file, summary(&found));
        let found = analyze_query(&QueryRequest {
            language: LanguageId::Cql,
            platform: None,
            stack: None,
            text,
        });
        assert!(
            found.is_empty(),
            "{} through analyze_query: {:?}",
            entry.file,
            summary(&found)
        );
    }
}

#[test]
fn every_broken_twin_reports_its_fault() {
    for entry in manifest() {
        let name = twin(&entry.file);
        let text = fs::read_to_string(root().join(&entry.file)).unwrap();
        let broken = fs::read_to_string(root().join(&name)).unwrap();
        assert_ne!(broken, text, "{name} has no injected fault");
        let found = opentide_cql::analyze(&broken).diagnostics;
        assert!(
            found.iter().any(|d| d.code == entry.code),
            "{name} ({}): expected {}, got {:?}",
            entry.fault,
            entry.code,
            summary(&found)
        );
    }
}
