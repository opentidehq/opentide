//! `catalogs/bitdefender/criteria.toml` agrees with bitdefender-1.0, and the
//! spec's Bitdefender fixtures get the codes they name (#226).
//!
//! `testdata/conformance/bitdefender/spec-tables.md` is the spec's
//! `detection` and "Criteria catalogue" sections, verbatim. Its EDR table and
//! enum table must match the generated catalogue exactly:
//!
//! - `process`, `file`, `connection` and `registry`: the table lists every
//!   detection field. `connection` writes its XDR resources as
//!   `Connection.<Resource>.Name` for the resources named after it, and
//!   `Connection.<Resource>.Operation` for those and the ones after it;
//! - the enum table: every enumerated detection field of those targets: the
//!   EDR ones with their values in page order and File.Operation's sensors,
//!   and `Connection.<Resource>.Operation`: every XDR resource operation.

use opentide_tide::bitdefender::criteria;
use opentide_tide::{AnalyzeInput, analyze};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn dir() -> PathBuf {
    root().join("testdata/conformance/bitdefender")
}

fn tables() -> String {
    std::fs::read_to_string(dir().join("spec-tables.md")).expect("spec-tables.md")
}

/// The backticked names of a markdown text.
fn ticked(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

/// Rows of the markdown table whose header starts with `| {first} |`.
fn table_rows(text: &str, first: &str) -> Vec<Vec<String>> {
    let header = format!("| {first} |");
    let mut lines = text.lines().skip_while(|l| !l.starts_with(&header));
    assert!(lines.next().is_some(), "no table headed {header}");
    lines
        .skip(1)
        .take_while(|l| l.starts_with('|'))
        .map(|l| {
            l.trim_matches('|')
                .split(" | ")
                .map(|c| c.trim().to_string())
                .collect()
        })
        .collect()
}

#[test]
fn detection_targets_match_the_spec() {
    let text = tables();
    let row = table_rows(&text, "Field")
        .into_iter()
        .find(|r| r[0] == "`target`")
        .expect("target row");
    let spec: BTreeSet<String> = ticked(&row[4]).into_iter().collect();
    let catalogue: BTreeSet<String> = criteria()
        .targets
        .iter()
        .filter(|t| t.detection)
        .map(|t| t.name.clone())
        .collect();
    assert_eq!(catalogue, spec);
    // The exclusion-only targets the spec refuses.
    for name in ["flow", "bitbucket repository"] {
        let target = criteria().target(name).expect(name);
        assert!(!target.detection && target.exclusion, "{name}");
    }
}

/// The field names of a table cell, with `X.<Resource>.Name` and
/// `X.<Resource>.Operation` expanded over the bare resource names after them:
/// `.Name` for the resources after the first placeholder, `.Operation` for
/// those and the ones after the second.
fn expand(names: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut placeholders: Vec<(String, String)> = Vec::new();
    let mut resources: Vec<Vec<String>> = Vec::new();
    for name in names {
        if let Some((head, tail)) = name.split_once(".<Resource>.") {
            placeholders.push((head.to_string(), tail.to_string()));
            resources.push(Vec::new());
        } else if !name.contains('.') {
            resources
                .last_mut()
                .expect("a resource name after a placeholder")
                .push(name.clone());
        } else {
            out.insert(name.clone());
        }
    }
    for (i, (head, tail)) in placeholders.iter().enumerate() {
        // A later placeholder covers the resources of the earlier ones too.
        for list in &resources[..=i] {
            for resource in list {
                out.insert(format!("{head}.{resource}.{tail}"));
            }
        }
    }
    out
}

#[test]
fn edr_table_matches_the_catalogue() {
    let text = tables();
    let rows = table_rows(&text, "Target");
    let targets: Vec<String> = rows.iter().map(|r| ticked(&r[0]).remove(0)).collect();
    assert_eq!(targets, ["process", "file", "connection", "registry"]);
    for row in &rows {
        let target = ticked(&row[0]).remove(0);
        assert!(
            criteria().target(&target).is_some_and(|t| t.closed),
            "{target} is a closed target"
        );
        let spec = expand(&ticked(&row[1]));
        let catalogue: BTreeSet<String> = criteria()
            .detection_fields(&target)
            .map(|f| f.name.clone())
            .collect();
        assert_eq!(catalogue, spec, "{target}");
    }
    // No other target is closed.
    let closed: Vec<&str> = criteria()
        .targets
        .iter()
        .filter(|t| t.closed)
        .map(|t| t.name.as_str())
        .collect();
    assert_eq!(closed, ["process", "file", "connection", "registry"]);
}

#[test]
fn enum_table_matches_the_catalogue() {
    let text = tables();
    let rows = table_rows(&text, "Enum field");
    let mut spec_fields = BTreeSet::new();
    for row in &rows {
        let name = ticked(&row[0]).remove(0);
        // `Connection.<Resource>.Operation` (XDR): every resource operation,
        // with the values the catalogue lists.
        if let Some((head, tail)) = name.split_once(".<Resource>.") {
            assert!(row[0].contains("(XDR)"), "{}", row[0]);
            let operations: Vec<_> = criteria()
                .fields
                .iter()
                .filter(|f| {
                    f.detection
                        && f.name.split('.').count() == 3
                        && f.name.starts_with(&format!("{head}."))
                        && f.name.ends_with(&format!(".{tail}"))
                })
                .collect();
            assert!(!operations.is_empty(), "{name}");
            for field in operations {
                assert_eq!(field.kind, "enum", "{}", field.name);
                assert_eq!(field.availability, "xdr", "{}", field.name);
                assert!(!field.values.is_empty(), "{}", field.name);
                spec_fields.insert(field.name.clone());
            }
            continue;
        }
        let field = criteria().field(&name).expect(&name);
        assert_eq!(field.kind, "enum", "{name}");
        // Groups: `a`, `b` (EDR only); `c` (XDR only); `d`, ...
        let mut expected = Vec::new();
        for group in row[1].split("; ") {
            let sensor = if group.ends_with("(EDR only)") {
                "edr"
            } else if group.ends_with("(XDR only)") {
                "xdr"
            } else {
                field.availability.as_str()
            };
            for value in ticked(group) {
                expected.push((value, sensor.to_string()));
            }
        }
        let actual: Vec<(String, String)> = field
            .values
            .iter()
            .map(|v| (v.name.clone(), v.availability.clone()))
            .collect();
        assert_eq!(actual, expected, "{name}");
        spec_fields.insert(name);
    }
    let catalogue: BTreeSet<String> = criteria()
        .fields
        .iter()
        .filter(|f| {
            f.kind == "enum"
                && f.detection
                && ["process", "file", "connection", "registry"].contains(&f.target.as_str())
        })
        .map(|f| f.name.clone())
        .collect();
    assert_eq!(catalogue, spec_fields);
}

fn yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("fixture dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    files
}

fn bitdefender_findings(path: &Path) -> Vec<(String, bool)> {
    let source = std::fs::read_to_string(path).expect("fixture");
    let result = analyze(AnalyzeInput {
        path: "objects/rules/fixture.yaml",
        source: &source,
        workspace: &[],
        elastic_tenants: &[],
    });
    result
        .diagnostics
        .into_iter()
        .filter(|d| d.code.starts_with("bitdefender_"))
        .map(|d| (d.code, d.severity == opentide_core::Severity::Error))
        .collect()
}

#[test]
fn valid_fixtures_have_no_bitdefender_error() {
    let files = yaml_files(&dir().join("valid"));
    assert_eq!(files.len(), 3);
    for path in files {
        let errors: Vec<_> = bitdefender_findings(&path)
            .into_iter()
            .filter(|(_, error)| *error)
            .collect();
        assert!(errors.is_empty(), "{}: {errors:?}", path.display());
    }
}

#[test]
fn invalid_fixtures_report_their_code() {
    let files = yaml_files(&dir().join("invalid"));
    assert_eq!(files.len(), 4);
    for path in files {
        let source = std::fs::read_to_string(&path).expect("fixture");
        let expected = source
            .lines()
            .find_map(|l| l.strip_prefix("# Expected constraint code: "))
            .and_then(|l| l.split(['.', ' ']).next())
            .expect("an expected code")
            .to_string();
        let found = bitdefender_findings(&path);
        assert!(
            found
                .iter()
                .any(|(code, error)| *code == expected && *error),
            "{}: expected {expected}, found {found:?}",
            path.display()
        );
    }
}
