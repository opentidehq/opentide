//! Public KQL and SPL detections, plus the same queries with one injected fault.
//!
//! Sources and licenses: `testdata/conformance/external/SOURCES.md`.
//! Production rules use syntax the v1 grammars do not cover yet (`summarize
//! min =`, `between`, leading SPL macros, `stats ... BY`). The harness keeps
//! the full rule and checks the longest prefix the grammar accepts. An
//! injected `frobnicate` / `notacommand` on that prefix must be diagnosed.
//! The broken full file must still produce at least one diagnostic.

use opentide_core::codes;
use opentide_kql::{Profile, analyze as analyze_kql};
use opentide_spl::analyze as analyze_spl;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn kql_parses(text: &str) -> bool {
    analyze_kql(text, Profile::Sentinel)
        .diagnostics
        .iter()
        .all(|d| d.code != codes::KQL_PARSE_ERROR)
}

fn spl_parses(text: &str) -> bool {
    analyze_spl(text)
        .diagnostics
        .iter()
        .all(|d| d.code != codes::SPL_PARSE_ERROR)
}

fn longest_prefix(text: &str, parses: fn(&str) -> bool) -> Option<String> {
    let mut best = None;
    let mut acc = String::new();
    for (i, line) in text.lines().enumerate().take(16) {
        if i > 0 {
            acc.push('\n');
        }
        acc.push_str(line);
        if line.trim().is_empty() {
            continue;
        }
        if parses(&acc) {
            best = Some(acc.clone());
        } else if best.is_some() {
            break;
        }
    }
    best.filter(|s| s.lines().any(|l| l.contains('|')))
}

fn read_queries(dir: &Path, ext: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(ext) && !name.contains(".broken.") {
            out.push((name, fs::read_to_string(&path).unwrap()));
        }
    }
    out
}

#[test]
fn external_kql_prefixes_catch_injected_operators() {
    let dir = repo_root().join("testdata/conformance/external/kql");
    let queries = read_queries(&dir, ".kql");
    assert!(queries.len() >= 10, "expected a real KQL corpus");
    let mut caught = 0;
    for (name, text) in &queries {
        let broken = fs::read_to_string(dir.join(name.replace(".kql", ".broken.kql"))).unwrap();
        assert!(
            broken.contains("frobnicate") || broken.contains(".show "),
            "{name} broken twin has no injected fault"
        );
        assert!(
            !analyze_kql(&broken, Profile::Sentinel)
                .diagnostics
                .is_empty(),
            "{name} broken full query produced no diagnostic"
        );
        let Some(prefix) = longest_prefix(text, kql_parses) else {
            continue;
        };
        let mutated = if prefix.contains("| where ") {
            prefix.replacen("| where ", "| frobnicate ", 1)
        } else {
            format!("{prefix}\n| frobnicate x")
        };
        let result = analyze_kql(&mutated, Profile::Sentinel);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.code == codes::KQL_UNKNOWN_OPERATOR),
            "{name} prefix did not diagnose frobnicate"
        );
        caught += 1;
    }
    assert!(
        caught >= 5,
        "injected operator caught on only {caught} public KQL prefixes"
    );
}

#[test]
fn external_spl_prefixes_catch_injected_commands() {
    let dir = repo_root().join("testdata/conformance/external/spl");
    let queries = read_queries(&dir, ".spl");
    assert!(queries.len() >= 10, "expected a real SPL corpus");
    let mut caught = 0;
    for (name, text) in &queries {
        let broken = fs::read_to_string(dir.join(name.replace(".spl", ".broken.spl"))).unwrap();
        assert!(
            broken.contains("notacommand"),
            "{name} broken twin has no injected fault"
        );
        assert!(
            !analyze_spl(&broken).diagnostics.is_empty(),
            "{name} broken full query produced no diagnostic"
        );
        let stripped = text
            .lines()
            .skip_while(|l| l.trim().starts_with('`'))
            .collect::<Vec<_>>()
            .join("\n");
        let Some(prefix) = longest_prefix(&stripped, spl_parses) else {
            continue;
        };
        let mutated = format!("{prefix}\n| notacommand");
        let result = analyze_spl(&mutated);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.code == codes::SPL_UNKNOWN_COMMAND),
            "{name} prefix did not diagnose notacommand: {:?}",
            result
                .diagnostics
                .iter()
                .map(|d| d.code.as_str())
                .collect::<Vec<_>>()
        );
        caught += 1;
    }
    assert!(
        caught >= 2,
        "injected command caught on only {caught} public SPL prefixes"
    );
}
