//! YARA and YARA-L baselines on the tree-sitter engines (epic #1219, #1221 c).
//!
//! * Highlight goldens: `highlight` on a representative rule of each language
//!   against `crates/testdata/highlight/<language>/rule.json`, every token
//!   (span and capture) compared. A missing golden is written;
//!   `UPDATE_GOLDENS=1` rewrites it after an intended change.
//! * YARA editor baseline: for every `.yar`/`.yara` file under
//!   `crates/testdata`, the fold spans (`opentide_analysis::folding`) and the
//!   outline symbols with their selection ranges (`analyze().symbols`, the
//!   name span of each rule and string), one insta snapshot
//!   (`tests/snapshots/yara_baseline__editor.snap`). The language server's
//!   `selectionRange` is indentation based and does not read the parse tree,
//!   so the outline selection ranges are the parser-dependent selection data.
//!
//! After an intended change: `UPDATE_GOLDENS=1 INSTA_UPDATE=always cargo test
//! -p opentide-analysis --test yara_baseline`, then read the diff.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze, folding, highlight};
use opentide_core::LanguageId;
use serde_json::Value;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const YARA_RULE: &str = r#"import "pe"

private rule helper : tag1 tag2 {
  meta:
    author = "opentide"
    score = 75
    active = true
  strings:
    $text = "cmd.exe" ascii wide nocase fullword
    $b64 = "powershell" base64
    $hex = { 4D 5A ?? [2-4] ( 90 | CC ) ~00 }
    $re = /https?:\/\/[a-z0-9.]+/i
  condition:
    uint16(0) == 0x5A4D and filesize < 2MB and
    for any i in (1..#text) : ( @text[i] < 1024 ) and
    2 of ($text, $b64, $re) and pe.is_dll() and not $hex at entrypoint
}

// a comment
/* a block comment */
rule main {
  condition:
    helper and any of them
}
"#;

const YARAL_RULE: &str = r#"rule suspicious_logon {
  meta:
    author = "opentide"
    severity = "HIGH"
  events:
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.principal.hostname = $host
    $e1.security_result.action = "BLOCK"
    $e1.target.user.userid != /^svc_/ nocase
    $e2.metadata.event_type = "USER_LOGIN"
    $e2.principal.hostname = $host
    $e2.security_result.action = "ALLOW"
    $e1.metadata.event_timestamp.seconds < $e2.metadata.event_timestamp.seconds
  match:
    $host over 10m
  outcome:
    $risk_score = max(if($e1.principal.ip_geo_artifact.location.country_or_region = "RU", 90, 40))
    $users = array_distinct($e1.target.user.userid)
  condition:
    #e1 > 3 and $e2
}
"#;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Compares `highlight` of `src` with the golden `<dir>/<name>.json`, token
/// by token.
fn exact_golden(dir: &str, name: &str, language: LanguageId, src: &str) {
    let result = highlight(language, src);
    assert!(
        !result.tokens.is_empty(),
        "{dir}/{name}: highlight returned no tokens"
    );
    let path = repo_root()
        .join("crates/testdata/highlight")
        .join(dir)
        .join(format!("{name}.json"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    if std::env::var("UPDATE_GOLDENS").ok().as_deref() == Some("1") || !path.exists() {
        fs::write(&path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    }
    let expected: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let triples = |tokens: &[Value]| -> Vec<(u64, u64, String)> {
        tokens
            .iter()
            .map(|t| {
                (
                    t["span"]["start"].as_u64().unwrap(),
                    t["span"]["end"].as_u64().unwrap(),
                    t["capture"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let actual: Value = serde_json::to_value(&result).unwrap();
    assert_eq!(
        triples(actual["tokens"].as_array().unwrap()),
        triples(expected["tokens"].as_array().unwrap()),
        "{dir}/{name}: tokens differ from the golden (UPDATE_GOLDENS=1 to accept)"
    );
}

#[test]
fn yara_golden() {
    exact_golden("yara", "rule", LanguageId::Yara, YARA_RULE);
}

#[test]
fn yaral_golden() {
    exact_golden("yaral", "rule", LanguageId::Yaral, YARAL_RULE);
}

/// Every file below `dir`, recursively.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn yara_editor_baseline() {
    let root = repo_root().join("crates/testdata");
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    let mut files: Vec<(String, String)> = paths
        .into_iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .and_then(LanguageId::from_extension)
                == Some(LanguageId::Yara)
        })
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            // Offsets are taken on the committed (LF) bytes on every OS.
            let text = fs::read_to_string(&p).unwrap().replace("\r\n", "\n");
            // A corpus fixture's first line is its `prod:` tag, not YARA.
            let text = if rel.starts_with("corpus/") {
                text.lines().skip(1).collect::<Vec<_>>().join("\n")
            } else {
                text
            };
            (rel, text)
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no YARA files under crates/testdata");

    let mut out = String::new();
    for (path, text) in &files {
        let _ = writeln!(out, "== {path}");
        for span in folding(LanguageId::Yara, text).unwrap_or_default() {
            let _ = writeln!(out, "fold {}..{}", span.start, span.end);
        }
        let host = MemoryWorkspace {
            files: vec![(path.clone(), text.clone())],
        };
        let response = analyze(
            &host,
            AnalyzeRequest {
                uri: path.clone(),
                language: LanguageId::Yara,
                text: text.clone(),
            },
        );
        for s in &response.symbols {
            let _ = writeln!(
                out,
                "symbol {} {} {}:{}-{}:{}",
                s.kind,
                s.name,
                s.range.start.line,
                s.range.start.character,
                s.range.end.line,
                s.range.end.character
            );
        }
    }
    insta::assert_snapshot!("editor", out);
}
