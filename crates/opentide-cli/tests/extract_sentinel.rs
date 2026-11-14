//! `generate extract sentinel` (UC-4.4e, #834) against its tenant. A
//! snapshot case cannot run it: MSAL and azure-core stamp each request with
//! random ids. `tests/cassettes/sentinel/extract.json` was recorded with
//! those ids fixed (`client.py extract`); here the command runs in a copy of
//! the workspace (`tests/extract_sentinel/workspace`), its ids fixed the
//! same way, against that cassette: it must send exactly the cassette's
//! requests, and what it writes is held to a snapshot.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use opentide_cassette::{Cassette, Mode, Proxy, Redaction};
use opentide_cli::commands::extract::{Context, sentinel_with};
use opentide_cli::env::Env;
use opentide_cli::json::Json;

/// The credential the replayed tenant gets; redacted, as the recording's was.
const SECRET: &str = "replayed-credential-value";

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
        "requests not the cassette's: {unmatched:#?}"
    );
    (scratch, ws, report)
}

/// The run against the cassette: its outcome and every rule file it writes
/// under `Imported/`, held to a snapshot. It leaves no debug dump of the
/// listing in the working directory (the Python CLI wrote
/// `output-<tenant>.json` there on every run).
#[test]
fn sentinel_rules_are_extracted_as_the_snapshot_says() {
    let (_scratch, ws, report) = extract();
    assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome.failure);
    assert_eq!(
        report.outcome.data,
        vec![("import".to_owned(), Json::str("sentinel"))]
    );
    let dumped: Vec<_> = std::fs::read_dir(&ws)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("output-"))
        .collect();
    assert!(dumped.is_empty(), "{dumped:?}");
    let mut shown = format!(
        "status: {}\nmessage: {}\nsummary: {:?}\n",
        report.outcome.status, report.outcome.message, report.outcome.summary
    );
    for (path, bytes) in files(&ws, "Imported") {
        shown.push_str(&format!(
            "\n--- {path}\n{}",
            String::from_utf8(bytes).unwrap()
        ));
    }
    insta::assert_snapshot!("sentinel_extract", shown);
}

/// A rule whose field is of the wrong type is skipped and listed with the
/// rule's id and the field; the other rules are still imported (one such
/// rule used to fail the whole import with a Python exception).
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
