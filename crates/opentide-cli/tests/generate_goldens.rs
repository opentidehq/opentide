//! `generate` and `setup ci` against the oracle's recordings (UC-3.2, #824;
//! UC-3.2c, #916): every recorded case of the ported commands, run in-process through
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
    "generate.explorer",
    "generate.inflight",
    "generate.inflight.prune",
    "setup.ci",
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

/// Runs `args` in `ws` in json mode; the exit code and stdout.
fn run_json(ws: &Path, words: &[&str]) -> (i32, String) {
    run_json_with(ws, words, &[])
}

/// [`run_json`] with `extra` added to the environment.
fn run_json_with(ws: &Path, words: &[&str], extra: &[(&str, &str)]) -> (i32, String) {
    let sink: Sink = Arc::new(Mutex::new(Buffer::default()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = std::iter::once("--json")
        .chain(words.iter().copied())
        .map(str::to_owned)
        .collect();
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs(
        [
            ("HOME".to_owned(), home.display().to_string()),
            ("PATH".to_owned(), std::env::var("PATH").unwrap_or_default()),
            ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
            ("GIT_CONFIG_GLOBAL".to_owned(), "/dev/null".to_owned()),
        ]
        .into_iter()
        .chain(
            extra
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
        ),
    );
    let (mut out, mut err) = (Vec::new(), Buffer::default());
    let exit_code = run(&argv, &env, &host, &mut out, &mut err);
    (exit_code, String::from_utf8(out).unwrap())
}

/// The visibility export is written only when asked for, and a run without
/// it removes the one an earlier run wrote; an inflight shard of an open pull
/// request is previewed in the bundle, a newer version replacing the
/// committed object.
#[test]
fn the_explorer_publishes_only_what_this_run_chose() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let exports = ws.join(".opentide/exports");
    let visibility = exports.join("explorer.visibility.json");
    let (code, stdout) = run_json(
        &ws,
        &[
            "generate",
            "explorer",
            "--include-visibility",
            "--visibility-tlp",
            "GREEN ",
        ],
    );
    assert_eq!(code, 0, "{stdout}");
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&visibility).unwrap()).unwrap();
    assert_eq!(written["tlp"], "green");
    std::fs::write(
        ws.join(".opentide/inflight/00000000-0000-4000-8003-000000000001.json"),
        r#"{"schema": "inflight.shard::1.0", "object": {"name": "Previewed", "metadata": {"uuid": "00000000-0000-4000-8003-000000000001", "schema": "rule::1.0", "version": 2}, "configurations": {"splunk": {"status": "PRODUCTION"}}}}"#,
    )
    .unwrap();
    let (code, stdout) = run_json(&ws, &["generate", "explorer"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(!visibility.exists());
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(exports.join("explorer.bundle.json")).unwrap())
            .unwrap();
    let rule = &bundle["models"]["rule"]["00000000-0000-4000-8003-000000000001"];
    assert_eq!(rule["name"], "Previewed");
    assert_eq!(
        bundle["stagingIndex"]["productionObjects"],
        serde_json::json!(["00000000-0000-4000-8003-000000000001"])
    );
}

/// Runs git in `dir`, without the host's configuration.
fn git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// A rule changed on a feature branch gets a shard naming its file, and the
/// shard is pruned once the default branch holds that version.
#[test]
fn inflight_shards_follow_the_branch() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("vscode", &ws);
    git(&ws, &["init", "-q", "-b", "main"]);
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-q", "-m", "catalogue"]);
    git(&ws, &["checkout", "-q", "-b", "feature"]);
    let rules = ws.join("objects/rules");
    let rule = std::fs::read_dir(&rules)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .min()
        .unwrap();
    let text = std::fs::read_to_string(&rule).unwrap();
    let document = opentide_schema::node::load(&text).unwrap();
    let root = document.root().unwrap();
    let uuid = root
        .get("metadata")
        .and_then(|metadata| metadata.get("uuid"))
        .and_then(|uuid| uuid.value.as_str())
        .unwrap()
        .to_owned();
    std::fs::write(&rule, format!("{text}\n# changed\n")).unwrap();
    let (code, stdout) = run_json(&ws, &["generate", "inflight"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains("\"message\":\"Generated 1 file in "),
        "{stdout}"
    );
    let shard_path = ws.join(".opentide/inflight").join(format!("{uuid}.json"));
    let shard: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&shard_path).unwrap()).unwrap();
    assert_eq!(shard["schema"], "inflight.shard::1.0");
    assert_eq!(shard["object"]["metadata"]["uuid"], uuid.as_str());
    assert_eq!(shard["change"]["platform"], "local");
    let relative = rule
        .strip_prefix(&ws)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(shard["change"]["source_path"], relative.as_str());
    // The default branch holds the shard's version: pruned.
    let (code, stdout) = run_json(&ws, &["generate", "inflight", "prune"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains("\"message\":\"Removed 1 file in "),
        "{stdout}"
    );
    assert!(!shard_path.exists());
}

/// `setup ci` refuses what it cannot do before it writes anything, and
/// writes the `[promotion]` override a flag asks for beside the pipeline.
#[test]
fn setup_ci_refuses_then_writes() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let failure = |stdout: &str| -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(stdout).unwrap()["failure"].clone()
    };
    let (code, stdout) = run_json(&ws, &["setup", "ci", "azure"]);
    assert_eq!(code, 2, "{stdout}");
    assert_eq!(failure(&stdout)["code"], "usage_needs_input");
    assert_eq!(
        failure(&stdout)["message"],
        "--json cannot prompt for confirmation. Add --yes to write to '.'."
    );
    let (code, stdout) = run_json(
        &ws,
        &["setup", "ci", "github", "--default-branch", "a b", "--yes"],
    );
    assert_eq!(code, 2, "{stdout}");
    assert_eq!(failure(&stdout)["argument"], "--default-branch");
    assert_eq!(
        failure(&stdout)["message"],
        "Invalid value for '--default-branch': 'a b' cannot be written into a pipeline; use letters, digits, '.', '_', '/' and '-'"
    );
    let (code, stdout) = run_json(&ws, &["setup", "--name", "x", "ci", "github", "--yes"]);
    assert_eq!(code, 2, "{stdout}");
    assert_eq!(
        failure(&stdout)["message"],
        "Invalid value: --name configures `opentide setup` itself and would be ignored by `opentide setup ci`."
    );
    let (code, stdout) = run_json(
        &ws,
        &[
            "setup",
            "ci",
            "github",
            "--yes",
            "--promotion-target",
            "NOPE",
        ],
    );
    assert_eq!(code, 2, "{stdout}");
    assert!(
        failure(&stdout)["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid value for '--promotion-target': 'NOPE' is not a status in this repository's deployment.toml; use one of: DESIGN, "),
        "{stdout}"
    );
    assert!(!ws.join(".github").exists());
    let (code, stdout) = run_json(
        &ws,
        &[
            "setup",
            "--yes",
            "ci",
            "gitlab",
            "--no-promotion",
            "--default-branch",
            "main",
        ],
    );
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["files"],
        serde_json::json!([".gitlab-ci.yml", ".opentide/configurations/deployment.toml"])
    );
    assert_eq!(document["message"], "Wrote 2 files");
    assert_eq!(
        document["warnings"],
        serde_json::json!([
            "GitLab pipelines publish to $CI_DEFAULT_BRANCH; --default-branch is ignored."
        ])
    );
    assert_eq!(
        std::fs::read_to_string(ws.join(".opentide/configurations/deployment.toml")).unwrap(),
        "[promotion]\nenabled = false\n"
    );
    // Planned again, the pipeline is a change and the override already holds.
    let (code, stdout) = run_json(&ws, &["setup", "ci", "gitlab", "--plan", "--no-promotion"]);
    assert_eq!(code, 0, "{stdout}");
    let plan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        plan["steps"][0]["files"],
        serde_json::json!([{"path": ".gitlab-ci.yml", "action": "merge"}])
    );
    assert_eq!(
        plan["message"],
        "Plan: 1 file to write (0 new, 1 changed) · nothing written"
    );
}

/// The parsed document of a run's stdout.
fn document(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap()
}

/// `--include-visibility` reads the workspace's `visibility.toml`: a declared
/// source lists the rules that read it and leaves `undeclared`; a custom
/// table, which the KQL engine reports as unknown, is a read too; and a file
/// its model refuses is the report's `problem`.
#[test]
fn the_explorer_reports_declared_visibility() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let rule = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&rule).unwrap();
    assert!(text.contains("      SecurityEvent\n"));
    std::fs::write(
        &rule,
        text.replace("      SecurityEvent\n", "      MyCustom_CL\n"),
    )
    .unwrap();
    let configuration = ws.join(".opentide/configurations/visibility.toml");
    std::fs::write(
        &configuration,
        "[[logsources]]\nname = \"SecurityEvent\"\nsystem = \"sentinel\"\ndescription = \"Windows security events\"\n\n[logsources.columns.EventID]\ntype = \"int\"\n",
    )
    .unwrap();
    let visibility = ws.join(".opentide/exports/explorer.visibility.json");
    let (code, stdout) = run_json(&ws, &["generate", "explorer", "--include-visibility"]);
    assert_eq!(code, 0, "{stdout}");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&visibility).unwrap()).unwrap();
    assert_eq!(report["present"], true);
    assert_eq!(report["problem"], serde_json::Value::Null);
    let rows = report["logsources"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{report}");
    assert_eq!(rows[0]["name"], "SecurityEvent");
    assert_eq!(
        rows[0]["read_by"],
        serde_json::json!(["00000000-0000-4000-8003-000000000008"])
    );
    assert_eq!(
        rows[0]["columns"],
        serde_json::json!([{"name": "EventID", "type": "int", "description": ""}])
    );
    assert_eq!(
        report["systems"],
        serde_json::json!({"sentinel": {"logsources": 1, "with_columns": 1, "used": 1}})
    );
    let reads = report["reads"].as_array().unwrap();
    assert!(
        reads.contains(&serde_json::json!({
            "rule": "00000000-0000-4000-8003-000000000001",
            "system": "sentinel",
            "name": "MyCustom_CL",
            "field_path": "configurations.sentinel.query",
        })),
        "{report}"
    );
    let undeclared = report["undeclared"].as_array().unwrap();
    assert!(
        undeclared
            .iter()
            .all(|entry| entry["name"] != "SecurityEvent"),
        "{report}"
    );
    assert!(
        undeclared.contains(&serde_json::json!({
            "system": "sentinel",
            "name": "MyCustom_CL",
            "rules": ["00000000-0000-4000-8003-000000000001"],
            "system_declares": true,
        })),
        "{report}"
    );
    // A source without its `system` is refused by the model.
    std::fs::write(
        &configuration,
        "[[logsources]]\nname = \"SecurityEvent\"\ndescription = \"d\"\n",
    )
    .unwrap();
    let (code, stdout) = run_json(&ws, &["generate", "explorer", "--include-visibility"]);
    assert_eq!(code, 0, "{stdout}");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&visibility).unwrap()).unwrap();
    // As the oracle's report: nothing could be read, so nothing is present.
    assert_eq!(report["present"], false);
    assert_eq!(report["logsources"], serde_json::json!([]));
    let problem = report["problem"].as_str().unwrap();
    assert!(
        problem.starts_with("visibility.toml could not be read: ") && problem.contains("system"),
        "{problem}"
    );
}

/// `INFLIGHT_PATHS` names the change set outside git.
#[test]
fn inflight_paths_name_the_change_set() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let (code, stdout) = run_json_with(
        &ws,
        &["generate", "inflight"],
        &[(
            "INFLIGHT_PATHS",
            " objects/rules/rule-0003-splunk-spl.yaml, ",
        )],
    );
    assert_eq!(code, 0, "{stdout}");
    let shards: Vec<String> = std::fs::read_dir(ws.join(".opentide/inflight"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(shards, ["00000000-0000-4000-8003-000000000003.json"]);
}

fn has_git() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_ok()
}

/// The vscode fixture committed on `main`, checked out on `feature`; its
/// rule files, sorted.
fn feature_branch(ws: &Path) -> Vec<PathBuf> {
    fixture("vscode", ws);
    git(ws, &["init", "-q", "-b", "main"]);
    git(ws, &["add", "-A"]);
    git(ws, &["commit", "-q", "-m", "catalogue"]);
    git(ws, &["checkout", "-q", "-b", "feature"]);
    let mut rules: Vec<PathBuf> = std::fs::read_dir(ws.join("objects/rules"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    rules.sort();
    rules
}

/// A deleted object file has nothing to preview: only the changed one gets
/// a shard, locally and when a CI run's diff cannot be read (the work tree
/// again).
#[test]
fn inflight_skips_deleted_object_files() {
    if !has_git() {
        return;
    }
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    let rules = feature_branch(&ws);
    std::fs::remove_file(ws.join("objects/objectives/detect-lsass-access.yaml")).unwrap();
    let text = std::fs::read_to_string(&rules[0]).unwrap();
    std::fs::write(&rules[0], format!("{text}\n# changed\n")).unwrap();
    let inflight = ws.join(".opentide/inflight");
    let count = || std::fs::read_dir(&inflight).unwrap().count();
    let (code, stdout) = run_json(&ws, &["generate", "inflight"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains("\"message\":\"Generated 1 file in "),
        "{stdout}"
    );
    assert_eq!(count(), 1);
    std::fs::remove_dir_all(&inflight).unwrap();
    // A GitHub run without the pull request's refs falls back to the work tree.
    let (code, stdout) = run_json_with(
        &ws,
        &["generate", "inflight"],
        &[("GITHUB_ACTIONS", "true")],
    );
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(count(), 1);
    let shard: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            std::fs::read_dir(&inflight)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(shard["change"]["platform"], "github");
}

/// GitHub and Azure pipelines deploy from `origin/HEAD`'s branch; without
/// it, from the checked-out branch, with a warning when others exist.
#[test]
fn setup_ci_detects_the_default_branch() {
    if !has_git() {
        return;
    }
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    git(&ws, &["init", "-q", "-b", "trunk"]);
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-q", "-m", "catalogue"]);
    git(&ws, &["update-ref", "refs/remotes/origin/trunk", "HEAD"]);
    git(
        &ws,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/trunk",
        ],
    );
    git(&ws, &["checkout", "-q", "-b", "feature"]);
    let (code, stdout) = run_json(&ws, &["setup", "ci", "github", "--yes"]);
    assert_eq!(code, 0, "{stdout}");
    let written = document(&stdout);
    assert_eq!(written["default_branch"], "trunk");
    assert!(written.get("warnings").is_none(), "{stdout}");
    let (code, stdout) = run_json(&ws, &["setup", "ci", "azure", "--yes"]);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(document(&stdout)["default_branch"], "trunk");
    git(
        &ws,
        &["symbolic-ref", "--delete", "refs/remotes/origin/HEAD"],
    );
    let (code, stdout) = run_json(&ws, &["setup", "ci", "github", "--yes"]);
    assert_eq!(code, 0, "{stdout}");
    let written = document(&stdout);
    assert_eq!(written["default_branch"], "feature");
    assert_eq!(
        written["warnings"],
        serde_json::json!([
            "origin/HEAD is not set, so the pipeline targets the checked-out branch 'feature'. Re-run with --default-branch <branch> if another branch deploys."
        ])
    );
}

/// Only the platforms whose file enables them get validate query jobs; and
/// two different repository paths are refused before anything is written.
#[test]
fn setup_ci_reads_enabled_platforms_and_one_path() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    std::fs::create_dir_all(ws.join("other")).unwrap();
    let (code, stdout) = run_json(
        &ws,
        &[
            "setup", "--path", ".", "ci", "github", "--path", "other", "--yes",
        ],
    );
    assert_eq!(code, 2, "{stdout}");
    let refused = document(&stdout);
    assert_eq!(refused["failure"]["code"], "usage_invalid_value");
    assert_eq!(
        refused["failure"]["message"],
        "Invalid value: Pass the repository path once: . and other name different targets."
    );
    assert!(!ws.join(".github").exists());
    assert!(!ws.join("other/.github").exists());
    let splunk = ws.join(".opentide/configurations/platforms/splunk.toml");
    let text = std::fs::read_to_string(&splunk).unwrap();
    assert!(text.starts_with("[platform]\nenabled = true\n"));
    std::fs::write(
        &splunk,
        text.replacen("enabled = true", "enabled = false", 1),
    )
    .unwrap();
    let (code, stdout) = run_json(
        &ws,
        &["setup", "ci", "github", "--default-branch", "main", "--yes"],
    );
    assert_eq!(code, 0, "{stdout}");
    let platforms = document(&stdout)["platforms"].clone();
    let platforms: Vec<&str> = platforms
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    assert!(!platforms.contains(&"splunk"), "{platforms:?}");
    assert!(platforms.contains(&"sentinel"), "{platforms:?}");
    assert_eq!(platforms.len(), 8, "{platforms:?}");
}
