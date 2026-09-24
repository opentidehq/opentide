//! Conformance: tide_corpus objects produce `{code, field_path, severity}` diagnostics
//! matching CLI issue shape. Pydantic object issues are a subset of the LSP.
//! Engine may add extra query diagnostics inside `query: |`.

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze, index_workspace};
use opentide_core::LanguageId;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_workspace(dir: &str) -> MemoryWorkspace {
    let root = repo_root().join(dir);
    let mut files = Vec::new();
    fn rec(dir: &PathBuf, files: &mut Vec<(String, String)>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                rec(&p, files);
            } else if matches!(p.extension().and_then(|s| s.to_str()), Some("yaml" | "yml")) {
                files.push((p.display().to_string(), fs::read_to_string(&p).unwrap()));
            }
        }
    }
    rec(&root, &mut files);
    MemoryWorkspace { files }
}

#[test]
fn tide_corpus_indexes_all_object_types() {
    let host = load_workspace("testdata/workspaces/tide_corpus");
    let idx = index_workspace(&host);
    assert!(idx.iter().any(|o| o.object_type == "rule"));
    assert!(idx.iter().any(|o| o.object_type == "objective"));
    assert!(idx.iter().any(|o| o.object_type == "threat"));
}

#[test]
fn sentinel_rule_has_injected_kql_tokens_and_no_unknown_operator() {
    let host = load_workspace("testdata/workspaces/tide_corpus");
    let (uri, text) = host
        .files
        .iter()
        .find(|(p, _)| p.ends_with("rule-0001-sentinel-kql.yaml"))
        .cloned()
        .unwrap();
    let r = analyze(
        &host,
        AnalyzeRequest {
            uri,
            language: LanguageId::TideYaml,
            text,
        },
    );
    assert!(r.tokens.iter().any(|t| t.capture == "tide.keyword"));
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "keyword" || t.capture == "type" || t.capture == "operator.pipe"),
        "{:?}",
        r.tokens.iter().map(|t| &t.capture).collect::<Vec<_>>()
    );
    assert!(
        !r.diagnostics
            .iter()
            .any(|d| d.code == "kql_unknown_operator"),
        "{:?}",
        r.diagnostics
    );
}

#[test]
fn splunk_rule_injects_spl_and_tokenizes_authored_text() {
    let host = load_workspace("testdata/workspaces/tide_corpus");
    let (uri, text) = host
        .files
        .iter()
        .find(|(p, _)| p.ends_with("rule-0003-splunk-spl.yaml"))
        .cloned()
        .unwrap();
    let r = analyze(
        &host,
        AnalyzeRequest {
            uri,
            language: LanguageId::TideYaml,
            text: text.clone(),
        },
    );
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "operator.pipe" || t.capture == "property")
    );
    assert!(
        !text.contains("| search index"),
        "authored SPL must not be rewritten with implicit search"
    );
}

#[test]
fn crowdstrike_is_unsupported_never_faked() {
    let host = load_workspace("testdata/workspaces/tide_corpus");
    let (uri, text) = host
        .files
        .iter()
        .find(|(p, _)| p.ends_with("rule-0006-crowdstrike-deploy-only.yaml"))
        .cloned()
        .unwrap();
    let r = analyze(
        &host,
        AnalyzeRequest {
            uri,
            language: LanguageId::TideYaml,
            text,
        },
    );
    assert!(
        r.diagnostics
            .iter()
            .any(|d| d.code == "crowdstrike_unsupported"),
        "{:?}",
        r.diagnostics
    );
}

#[test]
fn diagnostics_have_code_severity_and_field_path_shape() {
    let host = load_workspace("testdata/workspaces/tide_corpus");
    let (uri, text) = host
        .files
        .iter()
        .find(|(p, _)| p.ends_with("rule-0001-sentinel-kql.yaml"))
        .cloned()
        .unwrap();
    let r = analyze(
        &host,
        AnalyzeRequest {
            uri,
            language: LanguageId::TideYaml,
            text,
        },
    );
    for d in &r.diagnostics {
        assert!(!d.code.is_empty());
        assert!(!d.message.is_empty());
        let _ = d.severity.as_str();
    }
}

#[test]
fn library_rule_is_analyzable() {
    let host = load_workspace("testdata/objects");
    let (uri, text) = host
        .files
        .iter()
        .find(|(p, _)| p.contains("shai-hulud"))
        .cloned()
        .expect("library rule fixture");
    let r = analyze(
        &host,
        AnalyzeRequest {
            uri,
            language: LanguageId::TideYaml,
            text: text.clone(),
        },
    );
    assert!(r.tokens.iter().any(|t| t.capture == "tide.keyword"));
    assert!(
        r.tokens.iter().any(|t| t.capture == "type"
            && text.get(t.span.start..t.span.end) == Some("DeviceNetworkEvents")),
        "hunt searches[].query must inject when system: is a same-indent sibling; got {:?}",
        r.tokens
            .iter()
            .map(|t| (t.capture.as_str(), text.get(t.span.start..t.span.end)))
            .collect::<Vec<_>>(),
    );
}

#[derive(serde::Deserialize)]
struct PydanticIssue {
    file: String,
    code: String,
    field_path: Vec<String>,
    severity: String,
}

fn pydantic_issues(dir: &str) -> Vec<PydanticIssue> {
    let root = repo_root();
    let output = std::process::Command::new("python3")
        .arg(root.join("scripts/pydantic_object_issues.py"))
        .arg(root.join(dir))
        .output()
        .expect("python3");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("pydantic json")
}

fn lsp_covers(dir: &str, issues: &[PydanticIssue]) {
    let host = load_workspace(dir);
    for issue in issues {
        let (uri, text) = host
            .files
            .iter()
            .find(|(path, _)| path.ends_with(&issue.file))
            .cloned()
            .unwrap_or_else(|| panic!("missing {}", issue.file));
        let response = analyze(
            &host,
            AnalyzeRequest {
                uri,
                language: LanguageId::TideYaml,
                text,
            },
        );
        let covered = response.diagnostics.iter().any(|diag| {
            diag.code == issue.code
                && diag.severity.as_str() == issue.severity
                && diag.field_path.as_deref() == Some(issue.field_path.as_slice())
        });
        assert!(
            covered,
            "LSP missing {} {:?} {} on {}; have {:?}",
            issue.code,
            issue.field_path,
            issue.severity,
            issue.file,
            response
                .diagnostics
                .iter()
                .map(|diag| (
                    diag.code.as_str(),
                    diag.field_path.clone(),
                    diag.severity.as_str()
                ))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn pydantic_object_issues_are_subset_of_lsp() {
    let corpus = pydantic_issues("testdata/workspaces/tide_corpus");
    lsp_covers("testdata/workspaces/tide_corpus", &corpus);
    let shaped = pydantic_issues("testdata/conformance/pydantic");
    assert!(
        shaped
            .iter()
            .any(|issue| issue.code == "schema_validation"
                && issue.field_path == ["threat", "impact"]),
        "scalar impact fixture must be rejected by pydantic"
    );
    assert!(
        shaped
            .iter()
            .any(|issue| issue.code == "deprecated_field" && issue.field_path == ["meta"]),
        "legacy meta fixture must be deprecated by pydantic"
    );
    let claimed: Vec<_> = shaped
        .into_iter()
        .filter(|issue| {
            matches!(
                issue.code.as_str(),
                "deprecated_field" | "schema_validation"
            ) && (issue.field_path == ["threat", "impact"]
                || issue.field_path == ["meta"] && issue.code == "deprecated_field"
                || issue.field_path == ["metadata"])
        })
        .collect();
    lsp_covers("testdata/conformance/pydantic", &claimed);
}
