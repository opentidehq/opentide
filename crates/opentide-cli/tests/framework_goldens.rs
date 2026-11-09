//! The framework's goldens: the oracle's recordings (`tests/golden/cases`)
//! of the cases the framework alone decides — usage errors, typos, hoisting,
//! `DEBUG='*'`, JSON indentation, `--version`, a missing `--repo` and
//! `opentide commands` in every mode — run in-process through
//! [`opentide_cli::run`] and compared byte for byte.
//!
//! Each case runs with the recording's environment and argv, the oracle's
//! version, and stdout and stderr as terminals in `human` mode and as pipes
//! otherwise, as `cargo xtask golden record` runs them. `duration_ms` is the
//! one value normalised, as the goldens normalise it.
//!
//! Intended differences are not here: `--help` and the help a bare `mcp`,
//! `lsp` or `new` prints to a person (clap's help, see
//! `tests/golden/APPROVED_DIFFS.toml` and the CHANGELOG), and the home screen.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken recording is a failure"
)]

use opentide_cli::env::Env;
use opentide_cli::json::{Json, document_text};
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The case ids this test replays: command, variants.
const CASES: &[(&str, &[&str])] = &[
    (
        "_root",
        &[
            "typo-command",
            "typo-root-option",
            "version",
            "repo-missing",
            "bare",
        ],
    ),
    (
        "commands",
        &[
            "default",
            "hoist-flags",
            "json-after",
            "debug-star",
            "indent-2",
            "indent-0",
            "typo-option",
            "extra-argument",
        ],
    ),
    ("validate", &["typo-option"]),
    ("lint", &["typo-choice"]),
    ("query", &["missing-option"]),
    ("setup.ci", &["missing-argument"]),
    ("rules", &["bare"]),
    ("generate.extract", &["bare"]),
    ("mcp", &["bare"]),
    ("lsp", &["bare"]),
    ("new", &["bare"]),
];

/// Recordings of those variants left out, and why.
const LEFT_OUT: &[(&str, &str)] = &[
    // A bare `opentide` prints the home screen (human) or the root's help:
    // the help is clap's (an approved difference) and the home screen needs
    // the workspace index (UC-3.5's `info`).
    ("_root/human/none/bare", "home screen"),
    ("_root/human/tide-corpus/bare", "home screen"),
    ("_root/plain/none/bare", "help"),
    ("_root/plain/tide-corpus/bare", "help"),
    ("_root/agent/none/bare", "help"),
    ("_root/agent/tide-corpus/bare", "help"),
    // `opentide mcp`, `lsp` and `new` print the group's help to a person
    // (exit 2), laid out by clap: the help difference.
    ("mcp/human/none/bare", "help"),
    ("mcp/plain/none/bare", "help"),
    ("lsp/human/none/bare", "help"),
    ("lsp/plain/none/bare", "help"),
    ("new/human/none/bare", "help"),
    ("new/plain/none/bare", "help"),
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

struct Outcome {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

fn replay(dir: &Path, scratch: &Path) -> Outcome {
    let case: toml::Table = std::fs::read_to_string(dir.join("case.toml"))
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
    let home = scratch.join("home");
    let tmp = scratch.join("tmp");
    let ws = scratch.join("ws");
    for folder in [&home, &tmp, &ws] {
        std::fs::create_dir_all(folder).unwrap();
    }
    match case["fixture"].as_str().unwrap() {
        "none" => {}
        "tide-corpus" => tide_corpus(&ws),
        other => panic!("{other}: a fixture this test does not lay out"),
    }
    let env = Env::from_pairs(case["env"].as_table().unwrap().iter().map(|(key, value)| {
        let value = value
            .as_str()
            .unwrap()
            .replace("<HOME>", &home.display().to_string())
            .replace("<TMP>", &tmp.display().to_string());
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
        cwd: Some(ws),
        // The recorder's pseudo-terminal: 100 columns.
        width: terminal.then_some(100),
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let exit_code = run(&argv, &env, &host, &mut out, &mut err);
    let duration = Regex::new(r#""duration_ms":( ?)\d+"#).unwrap();
    let stdout = duration
        .replace_all(&String::from_utf8(out).unwrap(), r#""duration_ms":${1}0"#)
        .into_owned();
    let stdout = without_engine_variable(&stdout);
    let stderr = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    Outcome {
        exit_code,
        stdout,
        stderr,
    }
}

/// The catalogue without its last `environment` row, `OPENTIDE_ENGINE`: the
/// variable UC-0.7 (#805) added after the oracle, at the end of the list so
/// that the oracle's list is a prefix of today's. The Python CLI prints it
/// too (`opentide.cli.services.introspect.environment`).
fn without_engine_variable(stdout: &str) -> String {
    let Ok(mut document) = Json::parse(stdout) else {
        return stdout.to_owned();
    };
    let Json::Object(members) = &mut document else {
        return stdout.to_owned();
    };
    let Some((_, Json::Array(rows))) = members.iter_mut().find(|(key, _)| key == "environment")
    else {
        return stdout.to_owned();
    };
    let last = rows.pop();
    assert_eq!(
        last.as_ref().and_then(|row| row.get("name")),
        Some(&Json::str("OPENTIDE_ENGINE")),
        "the catalogue's last variable is OPENTIDE_ENGINE"
    );
    document_text(&document, stdout.starts_with("{\n"))
}

/// The `tide-corpus` fixture as the recorder lays it out
/// (`xtask/src/golden/fixture.rs`), for what the framework reads: the
/// corpus, and its `Configurations/` as `.opentide/configurations/` (the
/// tenants the redactor reads). The objects' links are left out: no
/// framework case reads an object.
fn tide_corpus(ws: &Path) {
    let source = repo().join("tests/fixtures/tide_corpus/current");
    copy_tree(&source, ws);
    copy_tree(
        &source.join("Configurations"),
        &ws.join(".opentide/configurations"),
    );
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

fn recorded_exit_code(dir: &Path) -> i32 {
    let outcome: toml::Table = std::fs::read_to_string(dir.join("outcome.toml"))
        .unwrap()
        .parse()
        .unwrap();
    i32::try_from(outcome["exit_code"].as_integer().unwrap()).unwrap()
}

/// Every recording of the framework's cases, by id.
fn recordings() -> Vec<(String, PathBuf)> {
    let cases = repo().join("tests/golden/cases");
    let mut out = Vec::new();
    for (command, variants) in CASES {
        for mode in ["human", "plain", "json", "agent"] {
            let Ok(fixtures) = std::fs::read_dir(cases.join(command).join(mode)) else {
                continue;
            };
            for fixture in fixtures {
                let fixture = fixture.unwrap().path();
                for variant in *variants {
                    let dir = fixture.join(variant);
                    let id = format!(
                        "{command}/{mode}/{}/{variant}",
                        fixture.file_name().unwrap().to_string_lossy()
                    );
                    if dir.is_dir() && !LEFT_OUT.iter().any(|(left, _)| *left == id) {
                        out.push((id, dir));
                    }
                }
            }
        }
    }
    out.sort();
    out
}

#[test]
fn framework_goldens_are_identical() {
    let recordings = recordings();
    assert!(recordings.len() >= 60, "{} recordings", recordings.len());
    let scratch = std::env::temp_dir().join(format!("opentide-cli-goldens-{}", std::process::id()));
    let mut failures = Vec::new();
    for (index, (id, dir)) in recordings.iter().enumerate() {
        let outcome = replay(dir, &scratch.join(index.to_string()));
        let stdout = std::fs::read_to_string(dir.join("stdout")).unwrap();
        let stderr = std::fs::read_to_string(dir.join("stderr")).unwrap();
        let exit_code = recorded_exit_code(dir);
        if outcome.exit_code != exit_code {
            failures.push(format!("{id}: exit {} != {exit_code}", outcome.exit_code));
        }
        if outcome.stdout != stdout {
            failures.push(format!(
                "{id}: stdout\n--- oracle\n{stdout}\n--- rust\n{}",
                outcome.stdout
            ));
        }
        if outcome.stderr != stderr {
            failures.push(format!(
                "{id}: stderr\n--- oracle\n{stderr}\n--- rust\n{}",
                outcome.stderr
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn framework_goldens_left_out_exist() {
    let cases = repo().join("tests/golden/cases");
    for (id, _) in LEFT_OUT {
        let parts: Vec<&str> = id.splitn(4, '/').collect();
        let dir = cases
            .join(parts[0])
            .join(parts[1])
            .join(parts[2])
            .join(parts[3]);
        assert!(dir.is_dir(), "{id} names no recording");
    }
}
