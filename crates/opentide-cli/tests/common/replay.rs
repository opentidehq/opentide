//! Replaying the oracle's recordings in-process (UC-3.2, UC-3.5): each
//! recorded case run through [`opentide_cli::run`] on a fresh copy of its
//! fixture, with the goldens' normalisation (`opentide-compare`), compared
//! with the recording by the goldens' comparator (`opentide_compare::compare`,
//! as `cargo xtask golden check --engine compare` compares them) under
//! `APPROVED_DIFFS.toml`: exit code, stdout, stderr, and every file written.
//!
//! The fixtures laid out here are the static ones of `tests/golden/cases.toml`
//! (`none`, `empty`, `tide-corpus`, `tide-corpus-typo`, `vscode`); the
//! generated ones (`fault`, `heavy-small`) are `cargo xtask golden check
//! --engine compare`'s.

#![allow(dead_code, reason = "each test binary uses part of the helpers")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use opentide_compare::ledger::{Ledger, Usage};
use opentide_compare::normalise::{Normaliser, Volatile};
use opentide_compare::{FileState, Run};

/// A generated fixture laid out already (`cargo xtask corpus faults --out
/// DIR`, `cargo xtask corpus generate --seed 1 ... --out DIR`), named in
/// `OPENTIDE_REPLAY_FIXTURES` as `fault=DIR,heavy-small=DIR`.
pub fn generated(name: &str) -> Option<PathBuf> {
    let listed = std::env::var("OPENTIDE_REPLAY_FIXTURES").ok()?;
    listed.split(',').find_map(|pair| {
        let (key, dir) = pair.split_once('=')?;
        (key == name).then(|| PathBuf::from(dir))
    })
}

/// A case's root directory, named and placed as `cargo xtask golden check`
/// places it (`xtask/src/golden/run.rs`: `/tmp/golden-XXXXXX` on Unix,
/// whatever `TMPDIR` says). Paths in a frame or a message wrap by their
/// length, so a root of another length (`tempfile::tempdir()`'s
/// `.tmpXXXXXX`, or a `TMPDIR` elsewhere) wraps lines the real compare does
/// not, and a ledger entry drafted from this replay would not apply there.
pub fn case_root() -> tempfile::TempDir {
    let parent = if Path::new("/tmp").is_dir() {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    tempfile::Builder::new()
        .prefix("golden-")
        .rand_bytes(6)
        .tempdir_in(parent)
        .unwrap()
}

/// The fixtures this module lays out.
pub const FIXTURES: &[&str] = &["none", "empty", "tide-corpus", "tide-corpus-typo", "vscode"];

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[derive(Clone, Default)]
pub struct Buffer(pub Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn copy_tree(from: &Path, to: &Path) {
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
pub fn fixture(name: &str, ws: &Path) {
    if let Some(dir) = generated(name) {
        copy_tree(&dir, ws);
        return;
    }
    match name {
        "none" => {}
        "empty" => std::fs::create_dir_all(ws.join(".opentide")).unwrap(),
        "tide-corpus-typo" => {
            fixture("tide-corpus", ws);
            let path = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(text.matches("\nseverity: High\n").count(), 1);
            std::fs::write(
                &path,
                text.replace("\nseverity: High\n", "\nseverity: high\n"),
            )
            .unwrap();
        }
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
pub fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
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
pub fn dirs(root: &Path) -> std::collections::BTreeSet<String> {
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
pub fn recorded_files(dir: &Path, outcome: &toml::Table) -> BTreeMap<String, FileState> {
    let mut out = BTreeMap::new();
    for entry in outcome
        .get("files")
        .and_then(|files| files.as_array())
        .into_iter()
        .flatten()
    {
        let path = entry["path"].as_str().unwrap();
        if entry["change"].as_str() == Some("deleted") {
            out.insert(path.to_owned(), FileState::Deleted);
            continue;
        }
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
pub fn ledger() -> Ledger {
    Ledger::parse(
        &std::fs::read_to_string(repo().join("tests/golden/APPROVED_DIFFS.toml")).unwrap(),
    )
    .unwrap()
}

/// Replays the recording in `dir`; the differences found, if any.
pub fn replay(id: &str, dir: &Path, ledger: &Ledger, usage: &mut Usage) -> Vec<String> {
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
    let scratch = case_root();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    let (home, tmp, ws) = (root.join("home"), root.join("tmp"), root.join("ws"));
    for folder in [&home, &tmp, &ws] {
        std::fs::create_dir_all(folder).unwrap();
    }
    fixture(case["fixture"].as_str().unwrap(), &ws);
    // Every folder a recording names files under: the workspace, the
    // temporary directory (CI summaries), home (the state directory).
    // A recording's `tmp/` is `$TMPDIR`, `<TMP>/tmp`.
    std::fs::create_dir_all(tmp.join("tmp")).unwrap();
    let roots = [
        ("ws", ws.clone()),
        ("tmp", tmp.join("tmp")),
        ("home", home.clone()),
    ];
    let before: Vec<_> = roots
        .iter()
        .map(|(_, root)| (files(root), dirs(root)))
        .collect();
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
    let cwd = match case.get("cwd").and_then(|cwd| cwd.as_str()) {
        None | Some(".") => ws.clone(),
        Some(sub) => ws.join(sub),
    };
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: terminal,
        stderr_tty: terminal,
        log_sink: sink,
        cwd: Some(cwd),
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
    // `generate` prints its checklist once the work is done: no live display.
    if mode == "human" && id.starts_with("generate") && stderr.contains("\x1b[?25l") {
        problems.push(format!(
            "{id}: stderr draws a live display after the work is done"
        ));
    }
    let mut written = BTreeMap::new();
    for ((prefix, root), (files_before, folders_before)) in roots.iter().zip(&before) {
        use std::os::unix::fs::PermissionsExt;
        let after = files(root);
        for (path, bytes) in &after {
            if files_before.get(path) == Some(bytes) {
                continue;
            }
            let mode = std::fs::metadata(root.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            let bytes = normaliser
                .text(&String::from_utf8_lossy(bytes))
                .into_bytes();
            written.insert(
                format!("{prefix}/{path}"),
                FileState::Written { mode, bytes },
            );
        }
        for path in files_before.keys() {
            if !after.contains_key(path) {
                written.insert(format!("{prefix}/{path}"), FileState::Deleted);
            }
        }
        for folder in dirs(root).difference(folders_before) {
            let mode = std::fs::metadata(root.join(folder))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            written.insert(
                format!("{prefix}/{folder}"),
                FileState::Written {
                    mode: 0o040_000 | mode,
                    bytes: Vec::new(),
                },
            );
        }
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
    if let Ok(dump) = std::env::var("OPENTIDE_REPLAY_DUMP") {
        // The candidate's run, for `scripts/golden/ledger_entries.py`.
        let out = Path::new(&dump).join(id);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("stdout"), &candidate.stdout).unwrap();
        std::fs::write(out.join("stderr"), &candidate.stderr).unwrap();
        std::fs::write(out.join("exit_code"), candidate.exit_code.to_string()).unwrap();
        for (path, state) in &candidate.files {
            if let FileState::Written { mode, bytes } = state
                && mode & 0o040_000 == 0
            {
                let target = out.join("files").join(path);
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::write(target, bytes).unwrap();
            }
        }
    }
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

/// Replays every recorded case of `commands` on the fixtures this module lays
/// out, but `--help` (the Python launcher's, until UC-3.8) and `validate query
/// --live` (the tenants' check, Python's until UC-4.1); the problems, and
/// how many cases ran. A ledger entry of these commands that applied to
/// nothing is a problem when `complete`.
pub fn replay_commands(commands: &[&str], complete: bool) -> (Vec<String>, usize) {
    let cases = repo().join("tests/golden/cases");
    let ledger = ledger();
    let mut usage = Usage::default();
    let mut problems = Vec::new();
    let mut ran = 0;
    let filter = std::env::var("OPENTIDE_REPLAY_FILTER").unwrap_or_default();
    for command in commands {
        for mode in ["human", "plain", "json", "agent"] {
            let extra: Vec<&str> = ["fault", "heavy-small"]
                .into_iter()
                .filter(|name| generated(name).is_some())
                .collect();
            for fixture in FIXTURES.iter().chain(&extra) {
                let fixture_dir = cases.join(command).join(mode).join(fixture);
                let Ok(variants) = std::fs::read_dir(&fixture_dir) else {
                    continue;
                };
                let mut variants: Vec<PathBuf> =
                    variants.map(|entry| entry.unwrap().path()).collect();
                variants.sort();
                for dir in variants {
                    let id = format!(
                        "{command}/{mode}/{fixture}/{}",
                        dir.file_name().unwrap().to_string_lossy()
                    );
                    let case = std::fs::read_to_string(dir.join("case.toml")).unwrap();
                    let live = *command == "validate.query" && case.contains("\"--live\"");
                    if case.contains("\"--help\"") || live || !id.contains(&filter) {
                        continue;
                    }
                    problems.extend(replay(&id, &dir, &ledger, &mut usage));
                    ran += 1;
                }
            }
        }
    }
    if complete && filter.is_empty() {
        for (index, entry) in ledger.entries.iter().enumerate() {
            // `--help` cases are not replayed here (the Python launcher's help):
            // `cargo xtask golden check --engine compare` applies their entries.
            let elsewhere = ["fault", "heavy-small"].iter().any(|fixture| {
                entry.case.contains(&format!("/{fixture}/")) && generated(fixture).is_none()
            }) || entry.case.ends_with("/help");
            if commands.contains(&entry.command.replace(' ', ".").as_str())
                && !elsewhere
                && !usage.is_used(index)
            {
                problems.push(format!(
                    "APPROVED_DIFFS.toml entry {} ({} {}) applied to no case: it is stale",
                    index + 1,
                    entry.command,
                    entry.case
                ));
            }
        }
    }
    (problems, ran)
}
