//! `generate extract sentinel` against the oracle (UC-4.4e, #834). A golden
//! case cannot replay it: MSAL and azure-core stamp the oracle's requests
//! with random ids. `tests/cassettes/sentinel/extract.json` was recorded from
//! the oracle's command line with those ids fixed (`client.py extract`), and
//! the oracle's files and document in `tests/extract_sentinel/oracle/`. Here the
//! Rust command runs in a copy of the same workspace, its ids fixed the same
//! way, against that cassette: it must send exactly the oracle's requests,
//! and write each rule file as the oracle did, but for the differences
//! `tests/golden/APPROVED_DIFFS.toml` approves (case
//! `cassette:sentinel/extract`), and load to the oracle's data. Two things
//! the oracle did are left out on purpose: it dumped the listing to
//! `output-<tenant>.json` in the working directory, and it padded each file
//! name with a space at both ends ([`unpadded`]).

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use opentide_cassette::{Cassette, Mode, Proxy, Redaction};
use opentide_cli::commands::extract::{Context, sentinel_with};
use opentide_cli::env::Env;
use opentide_cli::json::Json;
use opentide_compare::{Case, FileState, Run};

/// The credential the replayed tenant gets; redacted, as the recording's was.
const SECRET: &str = "replayed-credential-value";
/// The ledger's case for this test's comparison.
const CASE: &str = "cassette:sentinel/extract";
const COMMAND: &str = "generate extract sentinel";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn here() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/extract_sentinel")
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Every file under `root` by its path from `root`, `/`-separated.
fn files(root: &Path, under: &str) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.join(under)];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative = path.strip_prefix(root).unwrap().to_string_lossy();
                out.insert(relative.replace('\\', "/"), std::fs::read(&path).unwrap());
            }
        }
    }
    out
}

/// The workspace after the Rust run, and the run's report.
fn extract() -> (tempfile::TempDir, PathBuf, opentide_cli::commands::Report) {
    extract_edited(|_| {})
}

/// [`extract`] with the answers the cassette replays changed by `edit`
/// (never the requests the run must send).
fn extract_edited(
    mut edit: impl FnMut(&mut String),
) -> (tempfile::TempDir, PathBuf, opentide_cli::commands::Report) {
    let text =
        std::fs::read_to_string(repo().join("tests/cassettes/sentinel/extract.json")).unwrap();
    let mut cassette = Cassette::parse(&text).unwrap();
    for interaction in &mut cassette.interactions {
        if let opentide_cassette::Body::Text(body) = &mut interaction.response.body {
            edit(body);
        }
    }
    cassette.digest = cassette.compute_digest();
    let proxy = Proxy::start(
        Mode::Replay { cassette },
        Redaction::new([SECRET.to_owned()]),
    )
    .unwrap();
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(proxy.ca_pem().as_bytes()).unwrap();
    let env = Env::from_pairs(
        proxy
            .client_env(ca.path().to_str().unwrap())
            .into_iter()
            .chain([("AZURE_CLIENT_SECRET".to_owned(), SECRET.to_owned())]),
    );
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    copy_tree(&here().join("workspace"), &ws);
    let connector = opentide_connectors::sentinel::Sentinel::new();
    let report = sentinel_with(
        &Context {
            repo: Some(ws.to_str().unwrap()),
            env: &env,
            cwd: &ws,
            proxy: None,
        },
        &connector,
    );
    let unmatched = proxy.verify();
    assert!(
        unmatched.is_empty(),
        "requests not the oracle's: {unmatched:#?}"
    );
    (scratch, ws, report)
}

/// The oracle's file name as the command writes it: the oracle named a file
/// `sanitize_filename(f'"{name}"')`, so each name had a space at both ends
/// (` Rule - soc .yaml`, ` Rule - soc  00000000.yaml` for a second rule of
/// that name); the command writes `Rule - soc.yaml`, `Rule - soc 00000000.yaml`.
fn unpadded(oracle: &str) -> String {
    let (folder, name) = oracle.rsplit_once('/').unwrap();
    let name = name.strip_prefix(' ').unwrap();
    let name = match name.strip_suffix(" .yaml") {
        Some(stem) => format!("{stem}.yaml"),
        None => {
            let (stem, id) = name.rsplit_once("  ").unwrap();
            format!("{stem} {id}")
        }
    };
    format!("{folder}/{name}")
}

fn as_data(path: &str, bytes: &[u8]) -> String {
    let text = std::str::from_utf8(bytes).unwrap();
    let loaded = opentide_schema::node::load(text)
        .unwrap_or_else(|error| panic!("{path}: {error:?}\n{text}"));
    opentide_compile::json::Json::from_node(loaded.root().unwrap()).to_compact()
}

#[test]
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn sentinel_rules_are_extracted_as_the_recorded_run_extracted_them() {
    let (_scratch, ws, report) = extract();

    // The document: the oracle's keys, message and counts.
    let oracle: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(here().join("oracle/result.json")).unwrap())
            .unwrap();
    assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome.failure);
    assert_eq!(report.outcome.status, oracle["status"].as_str().unwrap());
    assert_eq!(report.outcome.message, oracle["message"].as_str().unwrap());
    assert_eq!(
        report.outcome.data,
        vec![("import".to_owned(), Json::str("sentinel"))]
    );
    let summary: Vec<(String, i64)> = report
        .outcome
        .summary
        .iter()
        .map(|(key, value)| match value {
            Json::Int(count) => (key.clone(), *count),
            other => panic!("{key}: {other:?}"),
        })
        .collect();
    assert_eq!(
        summary,
        [
            (
                "imported".to_owned(),
                oracle["summary"]["imported"].as_i64().unwrap()
            ),
            (
                "skipped".to_owned(),
                oracle["summary"]["skipped"].as_i64().unwrap()
            ),
        ]
    );

    // No debug dump of the listing in the working directory (the oracle
    // wrote `output-<tenant>.json` there on every run).
    let dumped: Vec<_> = std::fs::read_dir(&ws)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("output-"))
        .collect();
    assert!(dumped.is_empty(), "{dumped:?}");

    // The rule files: named as the oracle named them without its padding,
    // and holding the oracle's bytes but for the approved differences, and
    // the oracle's data. They are compared under the oracle's names, which
    // the ledger's entries name.
    let oracle_files = files(&here().join("oracle"), "Imported");
    let written = files(&ws, "Imported");
    assert_eq!(
        written.keys().cloned().collect::<Vec<_>>(),
        [
            "Imported/Encoded PowerShell — Ünïcode - soc 00000000.yaml",
            "Imported/Encoded PowerShell — Ünïcode - soc.yaml",
            "Imported/Quotes  and  back slash  a  name  - soc.yaml",
            "Imported/Sign-in from a new country - soc.yaml",
        ]
    );
    let candidate_files: BTreeMap<String, Vec<u8>> = oracle_files
        .keys()
        .map(|path| {
            let bytes = written
                .get(&unpadded(path))
                .unwrap_or_else(|| panic!("{path}: not written as {}", unpadded(path)));
            (path.clone(), bytes.clone())
        })
        .collect();
    assert_eq!(candidate_files.len(), written.len());
    for (path, bytes) in &oracle_files {
        assert_eq!(
            as_data(path, &candidate_files[path]),
            as_data(path, bytes),
            "{path} loads to other data than the oracle's"
        );
    }
    let run = |files: &BTreeMap<String, Vec<u8>>| Run {
        exit_code: 0,
        stdout: Vec::new(),
        stderr: Vec::new(),
        files: files
            .iter()
            .map(|(path, bytes)| {
                (
                    format!("ws/{path}"),
                    FileState::Written {
                        mode: 0o644,
                        bytes: bytes.clone(),
                    },
                )
            })
            .collect(),
    };
    let ledger = opentide_compare::ledger::Ledger::parse(
        &std::fs::read_to_string(repo().join("tests/golden/APPROVED_DIFFS.toml")).unwrap(),
    )
    .unwrap();
    let mut usage = opentide_compare::ledger::Usage::default();
    let compared = opentide_compare::compare(
        Case {
            command: COMMAND,
            id: CASE,
        },
        &run(&oracle_files),
        &run(&candidate_files),
        &ledger,
        &mut usage,
    );
    assert!(
        compared.equal,
        "differences the ledger does not approve:\n{:#?}",
        compared.differences
    );
    // Every entry of this comparison applied: none is stale.
    for (index, entry) in ledger.entries.iter().enumerate() {
        if entry.case == CASE {
            assert!(
                usage.is_used(index),
                "APPROVED_DIFFS.toml entry {} ({:?} {}) applied nowhere: it is stale",
                index + 1,
                entry.target,
                entry.rule_text
            );
        }
    }
}

/// A rule whose field is of the wrong type is skipped and listed with the
/// rule's id and the field; the other rules are still imported (one such
/// rule used to fail the whole import).
#[test]
fn a_rule_with_a_mistyped_field_is_skipped_and_the_others_imported() {
    let typed = r#""queryPeriod": "PT2H""#;
    let mut edited = 0;
    let (_scratch, ws, report) = extract_edited(|body| {
        edited += body.matches(typed).count();
        *body = body.replace(typed, r#""queryPeriod": 3"#);
    });
    assert_eq!(edited, 1, "the cassette changed");
    assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome.failure);
    let skipped = report
        .outcome
        .data
        .iter()
        .find(|(key, _)| key == "skipped")
        .map(|(_, value)| value.clone());
    let Some(Json::Array(skipped)) = skipped else {
        panic!("no skipped list: {:?}", report.outcome.data);
    };
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    let name = skipped[0].get("name").and_then(Json::as_str).unwrap();
    let reason = skipped[0].get("reason").and_then(Json::as_str).unwrap();
    assert!(name.starts_with("Encoded PowerShell"), "{name}");
    assert!(reason.starts_with("rule "), "{reason}");
    assert!(
        reason.ends_with(": field `query_period` is not a string"),
        "{reason}"
    );
    assert!(
        report.outcome.message.ends_with(" · 1 skipped"),
        "{}",
        report.outcome.message
    );
    assert!(!files(&ws, "Imported").is_empty(), "nothing imported");
}
