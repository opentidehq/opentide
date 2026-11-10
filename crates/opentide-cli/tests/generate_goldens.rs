//! `generate` against the oracle's recordings (UC-3.2, #824): every recorded
//! case of the ported generate commands, run in-process through
//! [`opentide_cli::run`] on a fresh copy of its fixture, with the goldens'
//! normalisation (`opentide-compare`), compared with the recording by the
//! goldens' comparator (`opentide_compare::compare`, as `cargo xtask golden
//! check --engine compare` compares them) under `APPROVED_DIFFS.toml`: exit
//! code, stdout, stderr, and every file written.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken recording is a failure"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use opentide_compare::ledger::{Ledger, Usage};
use opentide_compare::normalise::{Normaliser, Volatile};
use opentide_compare::{FileState, Run};

/// The commands whose recordings this test replays.
const COMMANDS: &[&str] = &[
    "generate.exports",
    "generate.exports.navigator",
    "generate.exports.objects",
    "generate.exports.revisions",
];

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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

/// The fixture as `cargo xtask golden record` lays it out (`xtask/src/golden/fixture.rs`).
fn fixture(name: &str, ws: &Path) {
    match name {
        "none" => {}
        "tide-corpus" => {
            copy_tree(&repo().join("tests/fixtures/tide_corpus/current"), ws);
            copy_tree(
                &ws.join("Configurations"),
                &ws.join(".opentide/configurations"),
            );
            std::fs::create_dir_all(ws.join("objects")).unwrap();
            for (family, legacy) in [
                ("threats", "../Objects/Threat Vectors"),
                ("objectives", "../Objects/Detection Objectives"),
                ("rules", "../Objects/Detection Rules"),
            ] {
                std::os::unix::fs::symlink(legacy, ws.join("objects").join(family)).unwrap();
            }
            for dir in ["schemas", "templates", "exports", "inflight"] {
                std::fs::create_dir_all(ws.join(".opentide").join(dir)).unwrap();
            }
        }
        "vscode" => copy_tree(&repo().join("tests/golden/fixtures/vscode-workspace"), ws),
        other => panic!("{other}: a fixture this test does not lay out"),
    }
}

/// Every file under `root` (links not followed), by relative path.
fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(relative, std::fs::read(entry.path()).unwrap());
            }
        }
    }
    out
}

/// Every folder under `root` (links not followed), by relative path.
fn dirs(root: &Path) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(relative);
                pending.push(entry.path());
            }
        }
    }
    out
}

/// What the recording says the case wrote, by its path in the recording
/// (`ws/...`).
fn recorded_files(dir: &Path, outcome: &toml::Table) -> BTreeMap<String, FileState> {
    let mut out = BTreeMap::new();
    for entry in outcome
        .get("files")
        .and_then(|files| files.as_array())
        .into_iter()
        .flatten()
    {
        let path = entry["path"].as_str().unwrap();
        assert_ne!(entry["change"].as_str(), Some("deleted"), "{path}");
        let mode = u32::from_str_radix(entry["mode"].as_str().unwrap(), 8).unwrap();
        // As `cargo xtask golden check` reads a recording (`xtask/src/compare.rs` `run_of`).
        let state = match entry["kind"].as_str() {
            Some("dir") => FileState::Written {
                mode: 0o040_000 | mode,
                bytes: Vec::new(),
            },
            Some("file") => FileState::Written {
                mode,
                bytes: match entry.get("blob").and_then(|blob| blob.as_str()) {
                    Some(blob) => {
                        std::fs::read(repo().join("tests/golden/blobs").join(blob)).unwrap()
                    }
                    None => std::fs::read(dir.join("files").join(path)).unwrap(),
                },
            },
            other => panic!("{path}: a recorded {other:?} this test does not read"),
        };
        out.insert(path.to_owned(), state);
    }
    out
}

/// The ledger, as `cargo xtask golden check` reads it.
fn ledger() -> Ledger {
    Ledger::parse(
        &std::fs::read_to_string(repo().join("tests/golden/APPROVED_DIFFS.toml")).unwrap(),
    )
    .unwrap()
}

/// Replays the recording in `dir`; the differences found, if any.
fn replay(id: &str, dir: &Path, ledger: &Ledger, usage: &mut Usage) -> Vec<String> {
    let case: toml::Table = std::fs::read_to_string(dir.join("case.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let outcome: toml::Table = std::fs::read_to_string(dir.join("outcome.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let argv: Vec<String> = case["argv"]
        .as_array()
        .unwrap()
        .iter()
        .skip(1)
        .map(|arg| arg.as_str().unwrap().to_owned())
        .collect();
    let mode = case["mode"].as_str().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    let (home, tmp, ws) = (root.join("home"), root.join("tmp"), root.join("ws"));
    for folder in [&home, &tmp, &ws] {
        std::fs::create_dir_all(folder).unwrap();
    }
    fixture(case["fixture"].as_str().unwrap(), &ws);
    let before = files(&ws);
    let folders_before = dirs(&ws);
    let env = Env::from_pairs(case["env"].as_table().unwrap().iter().map(|(key, value)| {
        let value = value
            .as_str()
            .unwrap()
            .replace("<HOME>", &home.display().to_string())
            .replace("<TMP>", &tmp.display().to_string())
            .replace("<WS>", &ws.display().to_string());
        (key.clone(), value)
    }));
    let terminal = mode == "human";
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: terminal,
        stderr_tty: terminal,
        log_sink: sink,
        cwd: Some(ws.clone()),
        width: terminal.then_some(100),
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let exit_code = run(&argv, &env, &host, &mut out, &mut err);
    let today = opentide_compare::normalise::utc_date(std::time::SystemTime::now());
    let mut normaliser = Normaliser::new(
        &Volatile {
            literals: vec![
                (ws.display().to_string(), "<WS>".into()),
                (home.display().to_string(), "<HOME>".into()),
                (tmp.display().to_string(), "<TMP>".into()),
            ],
            dates: vec![today],
            ..Volatile::default()
        },
        &[],
        std::iter::empty(),
    );
    let stdout = normaliser.text(&String::from_utf8(out).unwrap());
    let stderr = normaliser.text(&String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap());
    let mut problems = Vec::new();
    if mode == "human" && stderr.contains("\x1b[?25l") {
        problems.push(format!(
            "{id}: stderr draws a live display after the work is done"
        ));
    }
    let mut written = BTreeMap::new();
    for (path, bytes) in files(&ws) {
        if before.get(&path) == Some(&bytes) {
            continue;
        }
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(ws.join(&path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        let bytes = normaliser
            .text(&String::from_utf8_lossy(&bytes))
            .into_bytes();
        written.insert(format!("ws/{path}"), FileState::Written { mode, bytes });
    }
    for folder in dirs(&ws).difference(&folders_before) {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(ws.join(folder))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        written.insert(
            format!("ws/{folder}"),
            FileState::Written {
                mode: 0o040_000 | mode,
                bytes: Vec::new(),
            },
        );
    }
    let oracle = Run {
        exit_code: i32::try_from(outcome["exit_code"].as_integer().unwrap()).unwrap(),
        stdout: std::fs::read(dir.join("stdout")).unwrap(),
        stderr: std::fs::read(dir.join("stderr")).unwrap(),
        files: recorded_files(dir, &outcome),
    };
    let candidate = Run {
        exit_code,
        stdout: stdout.into_bytes(),
        stderr: stderr.into_bytes(),
        files: written,
    };
    let command = case["command"].as_str().unwrap();
    let report = opentide_compare::compare(
        opentide_compare::Case { command, id },
        &oracle,
        &candidate,
        ledger,
        usage,
    );
    for difference in &report.differences {
        problems.push(format!(
            "{id}: {} {} {}\n--- oracle\n{}\n--- rust\n{}",
            difference.target,
            difference.kind.as_str(),
            difference
                .pointer
                .as_deref()
                .or(difference.at.as_deref())
                .unwrap_or_default(),
            difference.oracle,
            difference.candidate
        ));
    }
    problems
}

#[test]
fn generate_cases_are_the_oracles() {
    let cases = repo().join("tests/golden/cases");
    let ledger = ledger();
    let mut usage = Usage::default();
    let mut problems = Vec::new();
    let mut ran = 0;
    for command in COMMANDS {
        for mode in ["human", "plain", "json", "agent"] {
            for fixture in ["tide-corpus", "vscode"] {
                let fixture_dir = cases.join(command).join(mode).join(fixture);
                let Ok(variants) = std::fs::read_dir(&fixture_dir) else {
                    continue;
                };
                for variant in variants {
                    let dir = variant.unwrap().path();
                    let id = format!(
                        "{command}/{mode}/{fixture}/{}",
                        dir.file_name().unwrap().to_string_lossy()
                    );
                    problems.extend(replay(&id, &dir, &ledger, &mut usage));
                    ran += 1;
                }
            }
        }
    }
    assert!(ran >= 32, "only {ran} cases found");
    for (index, entry) in ledger.entries.iter().enumerate() {
        if COMMANDS.contains(&entry.command.replace(' ', ".").as_str()) && !usage.is_used(index) {
            problems.push(format!(
                "APPROVED_DIFFS.toml entry {} ({} {}) applied to no case: it is stale",
                index + 1,
                entry.command,
                entry.case
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n\n"));
}

/// The exports that rendered before one failed are on disk, as the oracle,
/// which writes them one after another, leaves them: a threat without
/// `metadata.version` fails the objects table after the Navigator layer.
#[test]
fn exports_before_a_failure_are_written() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let threat = ws.join("Objects/Threat Vectors/threat-0001-simulated-actor.yaml");
    let text = std::fs::read_to_string(&threat).unwrap();
    assert!(text.contains("  version: 1\n"));
    std::fs::write(&threat, text.replace("  version: 1\n", "")).unwrap();
    let sink: Sink = Arc::new(Mutex::new(Buffer::default()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.clone()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = ["--json", "generate", "exports"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), Buffer::default());
    let exit_code = run(&argv, &env, &host, &mut out, &mut err);
    let stdout = String::from_utf8(out).unwrap();
    assert_eq!(exit_code, 1, "{stdout}");
    assert!(
        stdout.contains("\"message\":\"exports: KeyError: 'version' while rendering 00000000-0000-4000-8001-000000000001\""),
        "{stdout}"
    );
    let exports = ws.join(".opentide/exports");
    assert!(exports.join("attack-navigator.json").is_file());
    assert!(!exports.join("objects.export.json").exists());
    assert!(!exports.join("revisions.export.json").exists());
}
