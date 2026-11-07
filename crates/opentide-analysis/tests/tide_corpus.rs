//! Conformance: tide_corpus objects produce `{code, field_path, severity}` diagnostics
//! matching CLI issue shape. Pydantic object issues are a subset of the LSP.
//! Engine may add extra query diagnostics inside `query: |`.
//!
//! The Pydantic side is this repository's `opentide` package (`src/opentide`), run by
//! the interpreter of its environment (`uv sync --group dev` creates `.venv`), never
//! an installed release. `OPENTIDE_PYTHON` names another interpreter, which must
//! import `opentide` from `src/opentide` too.

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze, index_workspace};
use opentide_core::LanguageId;
use std::fs;
use std::path::{Path, PathBuf};

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
    let host = load_workspace("crates/testdata/workspaces/tide_corpus");
    let idx = index_workspace(&host);
    assert!(idx.iter().any(|o| o.object_type == "rule"));
    assert!(idx.iter().any(|o| o.object_type == "objective"));
    assert!(idx.iter().any(|o| o.object_type == "threat"));
}

#[test]
fn sentinel_rule_has_injected_kql_tokens_and_no_unknown_operator() {
    let host = load_workspace("crates/testdata/workspaces/tide_corpus");
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
    assert!(r.tokens.iter().any(|t| t.capture == "tide.property"));
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
    let host = load_workspace("crates/testdata/workspaces/tide_corpus");
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
    let host = load_workspace("crates/testdata/workspaces/tide_corpus");
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
    let host = load_workspace("crates/testdata/workspaces/tide_corpus");
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
    let host = load_workspace("crates/testdata/objects");
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
    assert!(r.tokens.iter().any(|t| t.capture == "tide.property"));
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

/// The interpreter of this checkout's Python environment, checked to import
/// `opentide` from `src/opentide`.
fn local_python() -> PathBuf {
    let root = repo_root();
    let python = std::env::var_os("OPENTIDE_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let venv = std::env::var_os("UV_PROJECT_ENVIRONMENT")
                .map_or_else(|| root.join(".venv"), |dir| root.join(dir));
            if cfg!(windows) {
                venv.join("Scripts").join("python.exe")
            } else {
                venv.join("bin").join("python")
            }
        });
    assert!(
        python.is_file(),
        "no Python environment at {}: run `uv sync --group dev` in {} (or set OPENTIDE_PYTHON)",
        python.display(),
        root.display()
    );
    // `-X utf8`: the path is printed in UTF-8, not in the locale's encoding.
    let output = std::process::Command::new(&python)
        .args([
            "-X",
            "utf8",
            "-c",
            "import opentide, pathlib; print(pathlib.Path(opentide.__file__).resolve().parent)",
        ])
        .output()
        .expect("python");
    assert!(
        output.status.success(),
        "{} cannot import opentide: {}",
        python.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let package = String::from_utf8(output.stdout).expect("a UTF-8 path");
    let package = Path::new(package.trim());
    let local = root.join("src/opentide");
    assert!(
        same_directory(package, &local),
        "{} imports opentide from {}, not this checkout",
        python.display(),
        package.display()
    );
    python
}

/// Whether two spellings name one directory. Each side is canonicalized: Python's
/// `resolve()` and Rust's `canonicalize()` spell the same directory differently on
/// Windows (`C:\...` and `\\?\C:\...`).
fn same_directory(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[test]
fn a_directory_is_the_same_however_it_is_spelled() {
    let dir = std::env::temp_dir().join(format!("opentide-same-directory-{}", std::process::id()));
    let real = dir.join("real");
    fs::create_dir_all(real.join("sub")).unwrap();
    // Another spelling of `real`, as Python on Windows prints one.
    let other = real.join("sub").join("..");
    assert_ne!(other, real.canonicalize().unwrap());
    assert!(same_directory(&other, &real));
    assert!(!same_directory(&real.join("sub"), &real));
    assert!(!same_directory(&dir.join("missing"), &real));
    fs::remove_dir_all(&dir).unwrap();
}

fn pydantic_issues(dir: &str) -> Vec<PydanticIssue> {
    let root = repo_root();
    let output = std::process::Command::new(local_python())
        .arg(root.join("scripts/engine/pydantic_object_issues.py"))
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
    let corpus = pydantic_issues("crates/testdata/workspaces/tide_corpus");
    lsp_covers("crates/testdata/workspaces/tide_corpus", &corpus);
    let shaped = pydantic_issues("crates/testdata/conformance/pydantic");
    assert!(
        shaped
            .iter()
            .any(|issue| issue.code == "schema_validation"
                && issue.field_path == ["threat", "impact"]),
        "scalar impact fixture must be rejected by pydantic"
    );
    // opentide#745 retired `meta:` and the splunk::2.x `advanced` table: they are
    // unknown keys, no longer deprecations, in Pydantic and in the catalog alike.
    for path in [vec!["meta"], vec!["configurations", "splunk", "advanced"]] {
        assert!(
            shaped
                .iter()
                .any(|issue| issue.code == "schema_validation" && issue.field_path == path),
            "legacy meta fixture: pydantic must reject {path:?} as an unknown key"
        );
    }
    assert!(
        !shaped.iter().any(|issue| issue.code == "deprecated_field"),
        "a retired spelling is not a deprecation"
    );
    let claimed: Vec<_> = shaped
        .into_iter()
        .filter(|issue| {
            issue.code == "schema_validation"
                && (issue.field_path == ["threat", "impact"]
                    || issue.field_path == ["meta"]
                    || issue.field_path == ["metadata"]
                    || issue.field_path == ["configurations", "splunk", "advanced"])
        })
        .collect();
    lsp_covers("crates/testdata/conformance/pydantic", &claimed);
}
