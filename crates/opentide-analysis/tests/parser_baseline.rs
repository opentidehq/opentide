//! Parser baseline: what the engine reports for every raw query file under
//! `crates/testdata`, one insta snapshot per language
//! (`tests/snapshots/parser_baseline__<language>.snap`).
//!
//! The files are the production corpus (`crates/testdata/corpus/<language>/`,
//! analyzed without their `prod:` tag line, as the corpus gate reads them)
//! and every other file whose extension names a query language
//! (`LanguageId::from_extension`): the conformance sets with their `.broken.`
//! fault twins, and the vendor-oracle inputs. Each goes through
//! `opentide_analysis::analyze`, the entry point the language server calls for
//! a raw query document, and the snapshot keeps, per file, every diagnostic
//! (`code severity start-end message`, 0-based UTF-16 `line:character`) and
//! every highlight token (`start..end capture`, byte offsets).
//!
//! Tokens are not recorded for the external YARA rule sets
//! (`conformance/external/yara/`, 3,000-line vendor files): YARA moves to
//! YARA-X (#1225), so their tree-sitter tokens are not a parity target and
//! would add about 1.5 MB of unreviewable lines. Their diagnostics stay
//! complete, and every other file keeps both sections.
//!
//! What this protects: ADR 0012 replaces the tree-sitter parsers with
//! hand-written Rust ones. On valid input the swap must keep these snapshots
//! identical; a change on broken input (where error recovery differs) is a
//! reviewed snapshot diff, never an unread `cargo insta accept`.
//!
//! After an intended change: `INSTA_UPDATE=always cargo test -p
//! opentide-analysis --test parser_baseline`, then read the diff. CI sets
//! `INSTA_UPDATE=no`.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze};
use opentide_core::LanguageId;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata")
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

/// The raw query files of `language`, as (path relative to
/// `crates/testdata` with forward slashes, the text analyzed), sorted by path.
fn files(language: LanguageId) -> Vec<(String, String)> {
    let root = testdata();
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    let mut out: Vec<(String, String)> = paths
        .into_iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .and_then(LanguageId::from_extension)
                == Some(language)
        })
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            // A Windows checkout may convert these files to CRLF: offsets are
            // taken on the committed (LF) bytes on every OS.
            let text = fs::read_to_string(&p).unwrap().replace("\r\n", "\n");
            // A corpus fixture's first line is its `prod:` tag, not query text
            // in every language (Kibana KQL and Lucene have no comments).
            let text = if rel.starts_with("corpus/") {
                text.lines().skip(1).collect::<Vec<_>>().join("\n")
            } else {
                text
            };
            (rel, text)
        })
        .collect();
    out.sort();
    out
}

/// Paths whose highlight tokens are left out of the snapshot (see the module
/// documentation).
fn tokens_recorded(path: &str) -> bool {
    !path.starts_with("conformance/external/yara/")
}

fn one_line(message: &str) -> String {
    message.replace('\r', "\\r").replace('\n', "\\n")
}

fn baseline(language: LanguageId) -> String {
    let files = files(language);
    assert!(
        !files.is_empty(),
        "no {} files under crates/testdata",
        language.as_str()
    );
    let mut out = String::new();
    for (path, text) in &files {
        let host = MemoryWorkspace {
            files: vec![(path.clone(), text.clone())],
        };
        let response = analyze(
            &host,
            AnalyzeRequest {
                uri: path.clone(),
                language,
                text: text.clone(),
            },
        );
        let _ = writeln!(out, "== {path}");
        for d in &response.diagnostics {
            let _ = writeln!(
                out,
                "{} {} {}:{}-{}:{} {}",
                d.code,
                d.severity.as_str(),
                d.range.start.line,
                d.range.start.character,
                d.range.end.line,
                d.range.end.character,
                one_line(&d.message)
            );
        }
        if tokens_recorded(path) {
            for t in &response.tokens {
                let _ = writeln!(out, "{}..{} {}", t.span.start, t.span.end, t.capture);
            }
        }
    }
    out
}

macro_rules! baseline_tests {
    ($($test:ident => $language:expr),* $(,)?) => {
        $(
            #[test]
            fn $test() {
                let language = $language;
                insta::assert_snapshot!(language.as_str(), baseline(language));
            }
        )*
    };
}

baseline_tests! {
    cql => LanguageId::Cql,
    datadog => LanguageId::Datadog,
    eql => LanguageId::Eql,
    esql => LanguageId::Esql,
    exabeam => LanguageId::Exabeam,
    falco => LanguageId::Falco,
    kql => LanguageId::Kql,
    kuery => LanguageId::Kuery,
    lucene => LanguageId::Lucene,
    spl => LanguageId::Spl,
    yara => LanguageId::Yara,
    yaral => LanguageId::Yaral,
}

/// A query language added to the engine gets a baseline above.
#[test]
fn every_query_language_has_a_baseline() {
    let mut languages: Vec<&str> = LanguageId::QUERY_LANGUAGES
        .iter()
        .map(|l| l.as_str())
        .collect();
    languages.sort_unstable();
    assert_eq!(
        languages,
        [
            "cql", "datadog", "eql", "esql", "exabeam", "falco", "kql", "kuery", "lucene", "spl",
            "yara", "yaral"
        ]
    );
}
