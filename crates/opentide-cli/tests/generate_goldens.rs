//! `generate` against the oracle's recordings (UC-3.2, #824): every recorded
//! case of the ported generate commands, run in-process through
//! [`opentide_cli::run`] on a fresh copy of its fixture, with the goldens'
//! normalisation (`opentide-compare`), compared with the recording: exit
//! code, stdout, stderr, and every file written, byte for byte.

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
use opentide_compare::normalise::{Normaliser, Volatile};

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

/// What the recording says the case wrote under `ws/`.
fn recorded_files(dir: &Path, outcome: &toml::Table) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for entry in outcome
        .get("files")
        .and_then(|files| files.as_array())
        .into_iter()
        .flatten()
    {
        let path = entry["path"].as_str().unwrap();
        if entry["kind"].as_str() != Some("file") {
            continue;
        }
        let Some(relative) = path.strip_prefix("ws/") else {
            continue;
        };
        let bytes = match entry.get("blob").and_then(|blob| blob.as_str()) {
            Some(blob) => std::fs::read(repo().join("tests/golden/blobs").join(blob)).unwrap(),
            None => std::fs::read(dir.join("files").join(path)).unwrap(),
        };
        out.insert(relative.to_owned(), bytes);
    }
    out
}

/// Replays the recording in `dir`; the differences found, if any.
fn replay(id: &str, dir: &Path) -> Vec<String> {
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
    let expected_code = outcome["exit_code"].as_integer().unwrap();
    if i64::from(exit_code) != expected_code {
        problems.push(format!(
            "{id}: exit {exit_code}, the oracle's {expected_code}"
        ));
    }
    for (name, got) in [("stdout", &stdout), ("stderr", &stderr)] {
        let want = std::fs::read_to_string(dir.join(name)).unwrap();
        if *got != want {
            problems.push(format!(
                "{id}: {name}\n--- oracle\n{want:?}\n--- rust\n{got:?}"
            ));
        }
    }
    let after = files(&ws);
    let written: BTreeMap<String, Vec<u8>> = after
        .into_iter()
        .filter(|(path, bytes)| before.get(path) != Some(bytes))
        .collect();
    let want = recorded_files(dir, &outcome);
    let paths = |files: &BTreeMap<String, Vec<u8>>| files.keys().cloned().collect::<Vec<_>>();
    if paths(&written) != paths(&want) {
        problems.push(format!(
            "{id}: wrote {:?}, the oracle {:?}",
            paths(&written),
            paths(&want)
        ));
    }
    for (path, bytes) in &want {
        if let Some(got) = written.get(path) {
            let got = normaliser.text(&String::from_utf8_lossy(got));
            if got.as_bytes() != bytes.as_slice() {
                problems.push(format!("{id}: {path} differs from the oracle's"));
            }
        }
    }
    problems
}

#[test]
fn generate_cases_are_the_oracles() {
    let cases = repo().join("tests/golden/cases");
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
                    problems.extend(replay(&id, &dir));
                    ran += 1;
                }
            }
        }
    }
    assert!(ran >= 32, "only {ran} cases found");
    assert!(problems.is_empty(), "{}", problems.join("\n\n"));
}
