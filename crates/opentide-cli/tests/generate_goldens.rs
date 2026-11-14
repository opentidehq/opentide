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

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};

#[path = "common/replay.rs"]
mod replay;
use replay::{Buffer, fixture};

/// The commands whose recordings this test replays.
const COMMANDS: &[&str] = &[
    "generate.exports",
    "generate.exports.navigator",
    "generate.exports.objects",
    "generate.exports.revisions",
    "generate.docs",
    "generate.docs.rules",
    "generate.docs.objectives",
    "generate.docs.threats",
    "generate.docs.index",
    "generate.explorer",
    "generate.inflight",
    "generate.inflight.prune",
    "setup.ci",
];

#[test]
fn generate_cases_are_the_oracles() {
    let (problems, ran) = replay::replay_commands(COMMANDS, true);
    assert!(ran >= 32, "only {ran} cases found");
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
        version: "0.28.1".into(),
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
        stdout.contains(r#""message":"exports: KeyError: \"version\" while rendering 00000000-0000-4000-8001-000000000001""#),
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
        version: "0.28.1".into(),
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
        "Invalid value for '--default-branch': \"a b\" cannot be written into a pipeline; use letters, digits, '.', '_', '/' and '-'"
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
            .starts_with("Invalid value for '--promotion-target': \"NOPE\" is not a status in this repository's deployment.toml; use one of: DESIGN, "),
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

/// `--promotion-target` reads the statuses from the merged configuration,
/// unchecked, as the oracle does: a `paths.toml` its model refuses (a legacy
/// `[paths.core]` table) does not stop it (#957).
#[test]
fn setup_ci_reads_the_statuses_of_a_refused_paths_toml() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("vscode-docs-folder", &ws);
    let (code, stdout) = run_json(
        &ws,
        &[
            "setup",
            "ci",
            "github",
            "--promotion-target",
            "STAGING",
            "--yes",
        ],
    );
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(
        std::fs::read_to_string(ws.join(".opentide/configurations/deployment.toml")).unwrap(),
        "[promotion]\npromotion_target = \"STAGING\"\n"
    );
    // A status the merged files do not define is still refused.
    let (code, stdout) = run_json(
        &ws,
        &[
            "setup",
            "ci",
            "github",
            "--promotion-target",
            "NOPE",
            "--yes",
        ],
    );
    assert_eq!(code, 2, "{stdout}");
    assert!(
        document(&stdout)["failure"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid value for '--promotion-target': \"NOPE\" is not a status in this repository's deployment.toml; use one of: DESIGN, "),
        "{stdout}"
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
            "origin/HEAD is not set, so the pipeline targets the checked-out branch \"feature\". Re-run with --default-branch <branch> if another branch deploys."
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

/// Runs the CLI in-process at `ws`; the exit code and stdout.
fn run_at(ws: &Path, words: &[&str]) -> (i32, String) {
    let sink: Sink = Arc::new(Mutex::new(Buffer::default()));
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), Buffer::default());
    let exit_code = run(&argv, &env, &host, &mut out, &mut err);
    (exit_code, String::from_utf8(out).unwrap())
}

/// Runs git in `ws`, with no system configuration and `ws` as its home.
fn git_at(ws: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(ws)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        // No automatic maintenance or gc: either works in `.git` in the
        // background after a commit, while the test reads the repository (#934).
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "maintenance.auto")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_CONFIG_KEY_1", "gc.auto")
        .env("GIT_CONFIG_VALUE_1", "0")
        .env("HOME", ws)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// `generate docs --changed` after a rule is renamed: its page moves (the old
/// one is removed), and the pages of the objective and threat above it are
/// rewritten; nothing else is.
#[test]
fn changed_docs_rewrite_a_renamed_rule_and_its_parents() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    git_at(&ws, &["init", "-q", "-b", "main"]);
    git_at(&ws, &["add", "-A"]);
    git_at(&ws, &["commit", "-q", "-m", "base"]);
    let rule = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&rule).unwrap();
    std::fs::write(
        &rule,
        text.replacen("name: Sentinel KQL Rule", "name: Renamed Sentinel Rule", 1),
    )
    .unwrap();
    let docs = ws.join("docs");
    let before_defender = std::fs::metadata(docs.join("rules/defender-kql-rule.md"))
        .unwrap()
        .modified()
        .unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--changed"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["changed_paths"],
        serde_json::json!(["Objects/Detection Rules/rule-0001-sentinel-kql.yaml"])
    );
    assert_eq!(
        document["changed_uuids"],
        serde_json::json!(["00000000-0000-4000-8003-000000000001"])
    );
    assert_eq!(
        document["targets"],
        serde_json::json!([
            "00000000-0000-4000-8001-000000000001",
            "00000000-0000-4000-8002-000000000001",
            "00000000-0000-4000-8003-000000000001"
        ])
    );
    assert_eq!(
        document["scopes"],
        serde_json::json!(["objective", "rule", "threat"])
    );
    assert_eq!(
        document["counts"],
        serde_json::json!({"rules": 1, "objectives": 1, "threats": 1})
    );
    assert_eq!(document["removed"], 1);
    assert!(docs.join("rules/renamed-sentinel-rule.md").is_file());
    assert!(!docs.join("rules/sentinel-kql-rule.md").exists());
    let objective =
        std::fs::read_to_string(docs.join("objectives/credential-access-objective.md")).unwrap();
    assert!(objective.contains("[Renamed Sentinel Rule](../rules/renamed-sentinel-rule.md)"));
    let after_defender = std::fs::metadata(docs.join("rules/defender-kql-rule.md"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        before_defender, after_defender,
        "an unrelated page was rewritten"
    );
    // Nothing changed against HEAD once it is committed: nothing is written.
    git_at(&ws, &["add", "-A"]);
    git_at(&ws, &["commit", "-q", "-m", "renamed"]);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--changed"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["message"],
        "No changed object documentation detected"
    );
    assert_eq!(document["changed_paths"], serde_json::json!([]));
}

/// A scoped run with `--changed` is a usage error, and two flags write both
/// families (`--rules --threats` used to write rules only).
#[test]
fn docs_scopes() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--rules", "--changed"]);
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.contains("\"code\":\"usage_error\""), "{stdout}");
    assert!(stdout.contains("\"argument\":\"--changed\""), "{stdout}");
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--rules", "--threats"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["scopes"], serde_json::json!(["rules", "threats"]));
    assert_eq!(
        document["counts"],
        serde_json::json!({"rules": 10, "objectives": 0, "threats": 1})
    );
    assert!(ws.join("docs/threats/simulated-actor.md").is_file());
    assert!(!ws.join("docs/objectives").exists());
}

/// Documentation previews open pull requests: a shard of a newer version
/// replaces the object for the run, a shard of a new object adds its page,
/// and a raw shard of the same version does not replace the file's object.
#[test]
fn docs_preview_the_inflight_shards() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let threat_file = ws.join("Objects/Threat Vectors/threat-0001-simulated-actor.yaml");
    let rule_file = ws.join("Objects/Detection Rules/rule-0002-defender-kql.yaml");
    let yaml = |path: &Path| -> serde_json::Value {
        let text = std::fs::read_to_string(path).unwrap();
        let document = opentide_schema::node::load(&text).unwrap();
        let json = opentide_compile::json::Json::from_node(document.root().unwrap());
        serde_json::from_str(&json.to_compact()).unwrap()
    };
    let mut threat = yaml(&threat_file);
    threat["name"] = "Previewed Actor".into();
    threat["metadata"]["version"] = 2.into();
    let mut added = yaml(&rule_file);
    added["name"] = "Pull Request Rule".into();
    added["metadata"]["uuid"] = "00000000-0000-4000-8003-00000000aaaa".into();
    let mut same = yaml(&rule_file);
    same["name"] = "Not Replaced".into();
    let inflight = ws.join(".opentide/inflight");
    std::fs::create_dir_all(&inflight).unwrap();
    let wrap = |object: serde_json::Value| {
        serde_json::json!({"schema": "inflight.shard::1.0", "object": object}).to_string()
    };
    std::fs::write(inflight.join("a.json"), wrap(threat)).unwrap();
    std::fs::write(inflight.join("b.json"), wrap(added)).unwrap();
    std::fs::write(inflight.join("c.json"), same.to_string()).unwrap();
    std::fs::write(inflight.join("d.json"), "not json").unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let docs = ws.join("docs");
    assert!(docs.join("threats/previewed-actor.md").is_file());
    assert!(!docs.join("threats/simulated-actor.md").exists());
    assert!(docs.join("rules/pull-request-rule.md").is_file());
    assert!(docs.join("rules/defender-kql-rule.md").is_file());
    assert!(!docs.join("rules/not-replaced.md").exists());
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["counts"],
        serde_json::json!({"rules": 11, "objectives": 1, "threats": 1})
    );
}

/// `generate docs --changed` after an objective is renamed: its page moves,
/// the threat above it is rewritten (a parent shows its children), and so is
/// every rule below it (their pages link to the objective by its name).
#[test]
fn changed_docs_rewrite_the_pages_below_a_renamed_objective() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    git_at(&ws, &["init", "-q", "-b", "main"]);
    git_at(&ws, &["add", "-A"]);
    git_at(&ws, &["commit", "-q", "-m", "base"]);
    let objective = ws.join("Objects/Detection Objectives/objective-0001-credential-access.yaml");
    let text = std::fs::read_to_string(&objective).unwrap();
    std::fs::write(
        &objective,
        text.replacen(
            "name: Credential Access Objective",
            "name: Renamed Objective",
            1,
        ),
    )
    .unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--changed"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["changed_uuids"],
        serde_json::json!(["00000000-0000-4000-8002-000000000001"])
    );
    // The upstream walk alone reaches the threat; the rules come from the
    // rename's downstream walk.
    assert_eq!(
        document["targets"],
        serde_json::json!([
            "00000000-0000-4000-8001-000000000001",
            "00000000-0000-4000-8002-000000000001",
            "00000000-0000-4000-8003-000000000001",
            "00000000-0000-4000-8003-000000000002",
            "00000000-0000-4000-8003-000000000003",
            "00000000-0000-4000-8003-000000000004",
            "00000000-0000-4000-8003-000000000005",
            "00000000-0000-4000-8003-000000000006",
            "00000000-0000-4000-8003-000000000007",
            "00000000-0000-4000-8003-000000000008",
            "00000000-0000-4000-8003-000000000009",
            "00000000-0000-4000-8003-0000005d1a90"
        ])
    );
    assert_eq!(
        document["counts"],
        serde_json::json!({"rules": 10, "objectives": 1, "threats": 1})
    );
    assert_eq!(document["removed"], 1);
    let docs = ws.join("docs");
    assert!(docs.join("objectives/renamed-objective.md").is_file());
    assert!(
        !docs
            .join("objectives/credential-access-objective.md")
            .exists()
    );
    for rule in ["sentinel-kql-rule.md", "sysdig-falco-rule.md"] {
        let page = std::fs::read_to_string(docs.join("rules").join(rule)).unwrap();
        assert!(
            page.contains("[Renamed Objective](../objectives/renamed-objective.md)"),
            "{rule}: {page}"
        );
        assert!(
            !page.contains("credential-access-objective"),
            "{rule}: {page}"
        );
    }
    let threat = std::fs::read_to_string(docs.join("threats/simulated-actor.md")).unwrap();
    assert!(
        threat.contains("[Renamed Objective](../objectives/renamed-objective.md)"),
        "{threat}"
    );
}

/// A run removes the generated pages no object writes any more, and leaves
/// the files it did not write: hand-written notes (even one with a Metadata
/// heading), README.md, and pages in subfolders.
#[test]
fn docs_remove_stale_pages_and_keep_hand_written_files() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let rules = ws.join("docs/rules");
    let generated = std::fs::read_to_string(rules.join("sentinel-kql-rule.md")).unwrap();
    std::fs::write(rules.join("old-rule.md"), &generated).unwrap();
    let notes = "# Notes\n\nHand-written.\n";
    let metadata_notes = "# Review\n\n## Metadata\n\n| UUID | to be assigned |\n";
    std::fs::write(rules.join("notes.md"), notes).unwrap();
    std::fs::write(rules.join("review.md"), metadata_notes).unwrap();
    std::fs::create_dir_all(rules.join("archive")).unwrap();
    std::fs::write(rules.join("archive/older-rule.md"), &generated).unwrap();
    std::fs::write(ws.join("docs/objectives/notes.md"), notes).unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["removed"], 1, "{stdout}");
    assert!(!rules.join("old-rule.md").exists());
    assert_eq!(
        std::fs::read_to_string(rules.join("notes.md")).unwrap(),
        notes
    );
    assert_eq!(
        std::fs::read_to_string(rules.join("review.md")).unwrap(),
        metadata_notes
    );
    assert!(rules.join("archive/older-rule.md").is_file());
    assert_eq!(
        std::fs::read_to_string(ws.join("docs/objectives/notes.md")).unwrap(),
        notes
    );
    assert!(rules.join("sentinel-kql-rule.md").is_file());
}

/// The inflight preview re-reads what the shards change: an objective's
/// shard renames a signal and adds one, a new rule's shard names the new
/// signal as its detection model, and another's names the objective; the
/// objective's page shows both rules and the signals as the shard has them.
/// A new threat's shard chains to the committed threat, whose page draws
/// the chain.
#[test]
fn docs_preview_shards_refresh_signals_and_references() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let yaml = |path: &Path| -> serde_json::Value {
        let text = std::fs::read_to_string(path).unwrap();
        let document = opentide_schema::node::load(&text).unwrap();
        let json = opentide_compile::json::Json::from_node(document.root().unwrap());
        serde_json::from_str(&json.to_compact()).unwrap()
    };
    let mut objective =
        yaml(&ws.join("Objects/Detection Objectives/objective-0001-credential-access.yaml"));
    objective["metadata"]["version"] = 2.into();
    objective["objective"]["signals"][0]["name"] = "Renamed logon signal".into();
    let mut signal = objective["objective"]["signals"][0].clone();
    signal["name"] = "Pull request signal".into();
    signal["uuid"] = "00000000-0000-4000-8099-000000000002".into();
    objective["objective"]["signals"]
        .as_array_mut()
        .unwrap()
        .push(signal);
    let rule = yaml(&ws.join("Objects/Detection Rules/rule-0002-defender-kql.yaml"));
    let mut on_signal = rule.clone();
    on_signal["name"] = "Signal Rule".into();
    on_signal["metadata"]["uuid"] = "00000000-0000-4000-8003-00000000aaaa".into();
    on_signal["detection_model"] = "00000000-0000-4000-8099-000000000002".into();
    let mut on_objective = rule;
    on_objective["name"] = "Objective Rule".into();
    on_objective["metadata"]["uuid"] = "00000000-0000-4000-8003-00000000bbbb".into();
    let mut chained = yaml(&ws.join("Objects/Threat Vectors/threat-0001-simulated-actor.yaml"));
    chained["name"] = "Chained Actor".into();
    chained["metadata"]["uuid"] = "00000000-0000-4000-8001-00000000cccc".into();
    chained["threat"]["chaining"] = serde_json::json!([{
        "relation": "preceeds",
        "vector": "00000000-0000-4000-8001-000000000001",
        "description": "Then the actor"
    }]);
    let inflight = ws.join(".opentide/inflight");
    std::fs::create_dir_all(&inflight).unwrap();
    for (name, object) in [
        ("a", objective),
        ("b", on_signal),
        ("c", on_objective),
        ("d", chained),
    ] {
        let shard = serde_json::json!({"schema": "inflight.shard::1.0", "object": object});
        std::fs::write(inflight.join(format!("{name}.json")), shard.to_string()).unwrap();
    }
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let page =
        std::fs::read_to_string(ws.join("docs/objectives/credential-access-objective.md")).unwrap();
    for line in [
        // The renamed signal and the pull request's signal both get a section.
        "### Renamed logon signal\n",
        "### Pull request signal\n",
        // The signals summary links each, and names the rule that implements one.
        "| [Renamed logon signal](#renamed-logon-signal) | Medium | Statistical | - | \
         *None yet* | - |\n",
        "| [Pull request signal](#pull-request-signal) | Medium | Statistical | - | \
         [Signal Rule](../rules/signal-rule.md) | Microsoft Defender for Endpoint `STAGING` |\n",
        // The related-objects table reaches the pull request's objects.
        "| Signal | [Pull request signal](credential-access-objective.md#pull-request-signal) | \
         Downstream |\n",
        "| Rule | [Signal Rule](../rules/signal-rule.md) | Downstream |\n",
        "| Rule | [Objective Rule](../rules/objective-rule.md) | Downstream |\n",
    ] {
        assert!(page.contains(line), "{line}: {page}");
    }
    assert!(!page.contains("Suspicious logon signal"), "{page}");
    let threat = std::fs::read_to_string(ws.join("docs/threats/simulated-actor.md")).unwrap();
    // The pull request's threat chains into this one: the page's own threat
    // first (thr1, outlined), the shard's second, linked the `preceeds` way.
    let section = &threat[threat.find("## Chaining").unwrap()..];
    for line in [
        "    thr1{{\"Simulated Actor\"}}\n",
        "    thr2{{\"Chained Actor\"}}\n",
        "    thr2 -->|\"preceeds\"| thr1\n",
        "    class thr1 focus\n",
    ] {
        assert!(section.contains(line), "{line}: {threat}");
    }
}

/// A stand-in Vulnerability-Lookup on the loopback, answering the records
/// and the EPSS score opentide 0.28.1 recorded from vulnerability.circl.lu
/// (`tests/fixtures/vulnerability_lookup/`): each request's line is
/// recorded, CVE-2024-3094's EPSS score answers 503, and every other
/// identifier is not known (`{}`).
fn vulnerability_lookup() -> (String, Arc<Mutex<Vec<String>>>) {
    use std::io::{BufRead, BufReader, Write};
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/vulnerability_lookup");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut header = String::new();
            while reader.read_line(&mut header).unwrap() > 2 {
                header.clear();
            }
            log.lock().unwrap().push(line.trim().to_owned());
            let target = line.split(' ').nth(1).unwrap_or_default();
            let path = target.split('?').next().unwrap_or_default();
            let (status, body) = match path {
                "/api/epss/CVE-2024-3094" => ("503 Service Unavailable", String::new()),
                "/api/vulnerability/CVE-2023-4966" => ("200 OK", "cve-2023-4966.json".to_owned()),
                "/api/vulnerability/CVE-2024-3094" => ("200 OK", "cve-2024-3094.json".to_owned()),
                "/api/epss/CVE-2023-4966" => ("200 OK", "epss-cve-2023-4966.json".to_owned()),
                _ => ("200 OK", String::new()),
            };
            let body = if body.is_empty() {
                if status.starts_with("200") {
                    "{}".to_owned()
                } else {
                    String::new()
                }
            } else {
                std::fs::read_to_string(fixtures.join(body)).unwrap()
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (base, seen)
}

/// A threat that lists CVEs, with `[cve] retrieve_details` on (the default):
/// its page is a table of each record's severity, EPSS score, exploitation
/// and weakness, asked of Vulnerability-Lookup once per identifier with its
/// linked records, then each CVE's EPSS score (UC-4.4, #834; 0.26.0); the
/// overview counts the CVEs with the highest score, and a warning names the
/// one CISA lists as exploited. With the setting off, the CVEs are links.
/// The page's CVE parts are opentide 0.28.1's, byte for byte, on the same
/// stand-in.
#[test]
fn docs_with_cve_details_fetch_each_record() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let threat = ws.join("Objects/Threat Vectors/threat-0001-simulated-actor.yaml");
    let mut text = std::fs::read_to_string(&threat).unwrap();
    text.push_str(
        "  cve:\n    - CVE-2023-4966\n    - CVE-2024-3094\n    - cve-2024-9999\n    - GCVE-0-2024-3094\n",
    );
    std::fs::write(&threat, text).unwrap();
    let (base, seen) = vulnerability_lookup();
    std::fs::write(
        ws.join(".opentide/configurations/documentation.toml"),
        format!("[cve]\nbase_url = \"{base}\"\n"),
    )
    .unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "threats"]);
    assert_eq!(code, 0, "{stdout}");
    let page = std::fs::read_to_string(ws.join("docs/threats/simulated-actor.md")).unwrap();
    assert!(
        page.contains("\n| CVE | 3 CVEs (highest CVSS 10.0, 1 known exploited) |\n"),
        "{page}"
    );
    assert!(
        page.contains(
            "\n> **Warning:** `CVE-2023-4966` (CISA KEV since 2023-10-18) is known to be \
             exploited in the wild.\n"
        ),
        "{page}"
    );
    let section = &page[page.find("## CVE").unwrap()..];
    // The CVE section ends where the next one, Detection coverage, begins.
    let section = &section[..section.find("\n## Detection coverage").unwrap()];
    // The bundled documentation.toml's `default_db_link` places the pages.
    const PAGES: &str = "https://vulnerability.circl.lu/vuln/";
    assert_eq!(
        section,
        format!(
            "## CVE\n\nIdentifiers link to [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu), \
             which aggregates CVE, GHSA, CSAF, NVD, and related feeds.\n\n\
             | Identifier | Severity | EPSS | Exploitation | Weakness | Published |\n\
             | --- | --- | --- | --- | --- | --- |\n\
             | [CVE-2023-4966]({PAGES}CVE-2023-4966) | **9.4** CRITICAL<br>CVSS 3.1 | 94.3%<br>top 0.3% \
             | **Known exploited**<br>CISA KEV, 2023-10-18 \
             | [CWE-119](https://cwe.mitre.org/data/definitions/119.html) Improper Restriction of \
             Operations within the Bounds of a Memory Buffer | 2023-10-10 |\n\
             | [CVE-2024-3094]({PAGES}CVE-2024-3094) | **10.0** CRITICAL<br>CVSS 3.1 | - \
             | None reported<br>CISA SSVC \
             | [CWE-506](https://cwe.mitre.org/data/definitions/506.html) Embedded Malicious Code \
             | 2024-03-29 |\n\
             | [CVE-2024-9999]({PAGES}CVE-2024-9999) | - | - | - | - | Not found in Vulnerability-Lookup. |\n\n\
             - **CVE-2023-4966**: Unauthenticated sensitive information disclosure. Affects Citrix \
             NetScaler ADC, Citrix NetScaler Gateway. Vector \
             `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`.\n\
             - **CVE-2024-3094**: Xz: malicious code in distributed source. Affects xz, Red Hat \
             Enterprise Linux 10, Red Hat Enterprise Linux 6, Red Hat Enterprise Linux 7 and 1 more. \
             Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`.\n\n\
             Could not resolve: `CVE-2024-9999`.\n\n\
             Vulnerability-Lookup returned no EPSS score for at least one identifier; those rows \
             show none.\n\n\
             *EPSS: FIRST's probability of exploitation in the next 30 days. Exploitation: CISA's \
             Known Exploited Vulnerabilities catalog, else its SSVC assessment.*\n"
        )
    );
    // GCVE-0-2024-3094 is CVE-2024-3094: one row, one request each; a CVE
    // the instance does not know has no EPSS request.
    assert_eq!(
        *seen.lock().unwrap(),
        [
            "GET /api/vulnerability/CVE-2023-4966?with_linked=true HTTP/1.1",
            "GET /api/epss/CVE-2023-4966 HTTP/1.1",
            "GET /api/vulnerability/CVE-2024-3094?with_linked=true HTTP/1.1",
            "GET /api/epss/CVE-2024-3094 HTTP/1.1",
            "GET /api/vulnerability/CVE-2024-9999?with_linked=true HTTP/1.1",
        ]
    );
    // An instance that cannot be reached: each row says so, and no warning.
    std::fs::write(
        ws.join(".opentide/configurations/documentation.toml"),
        "[cve]\nbase_url = \"http://127.0.0.1:1\"\ntimeout = 2\n",
    )
    .unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "threats"]);
    assert_eq!(code, 0, "{stdout}");
    let page = std::fs::read_to_string(ws.join("docs/threats/simulated-actor.md")).unwrap();
    assert!(page.contains("\n| CVE | 3 CVEs |\n"), "{page}");
    assert!(!page.contains("exploited in the wild"), "{page}");
    assert!(
        page.contains(&format!(
            "| [CVE-2023-4966]({PAGES}CVE-2023-4966) | - | - | - | - | Details unavailable from \
             Vulnerability-Lookup. |\n"
        )),
        "{page}"
    );
    assert!(
        page.contains(
            "\nVulnerability-Lookup was unreachable for at least one identifier; links still \
             point at the CIRCL record page.\n"
        ),
        "{page}"
    );
    // With the setting off, the page lists the CVEs as links, and asks nothing.
    std::fs::write(
        ws.join(".opentide/configurations/documentation.toml"),
        "[cve]\nretrieve_details = false\n",
    )
    .unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let page = std::fs::read_to_string(ws.join("docs/threats/simulated-actor.md")).unwrap();
    assert!(
        page.contains("- [CVE-2023-4966](https://vulnerability.circl.lu/vuln/CVE-2023-4966)\n"),
        "{page}"
    );
    assert!(page.contains("\n| CVE | 3 CVEs |\n"), "{page}");
    assert_eq!(seen.lock().unwrap().len(), 5);
}

/// `[paths.core] docs_folder` (CoreTIDE's docs folder) is not a key of
/// paths.toml: the oracle's `load_settings` falls back to it, but its paths
/// model refuses the table first, so the docs step fails and writes nothing,
/// neither under that folder nor under `docs/` (#936). Pinned here so a
/// later fallback cannot start writing pages the oracle never wrote, and the
/// failure stays the docs step's (`phase`), as the oracle reports it.
#[test]
fn docs_refuse_the_legacy_core_docs_folder() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("vscode-docs-folder", &ws);
    let before = replay::files(&ws);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 1, "{stdout}");
    let document = document(&stdout);
    assert_eq!(document["failure"]["code"], "command_failed", "{stdout}");
    assert_eq!(document["phase"], "docs", "{stdout}");
    let message = document["failure"]["message"].as_str().unwrap();
    assert!(message.starts_with("docs: paths.toml"), "{message}");
    assert!(message.contains("paths.core"), "{message}");
    assert!(!ws.join("site").exists());
    assert!(!ws.join("docs").exists());
    assert_eq!(replay::files(&ws), before);
}

/// A configuration that does not load fails the step of every `generate`
/// command, as the oracle reports it: the oracle reads the configuration
/// inside the phase, so the envelope leads with `phase`, the message with
/// the phase's name, and plain mode prints the failed checklist row before
/// the error. Opened before the step, the workspace's error was a bare
/// command error, with neither (#946). Nothing is written.
#[test]
fn generate_steps_fail_on_a_configuration_they_cannot_load() {
    for (words, step, phase) in [
        (&["generate", "exports"][..], "exports", "exports"),
        (
            &["generate", "exports", "navigator"][..],
            "exports navigator",
            "exports",
        ),
        (&["generate", "explorer"][..], "explorer", "explorer"),
        (&["generate", "inflight"][..], "inflight", "inflight"),
        (
            &["generate", "inflight", "prune"][..],
            "inflight prune",
            "inflight-prune",
        ),
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
        fixture("vscode-docs-folder", &ws);
        let before = replay::files(&ws);

        let json: Vec<&str> = std::iter::once("--json")
            .chain(words.iter().copied())
            .collect();
        let (code, stdout) = run_at(&ws, &json);
        assert_eq!(code, 1, "{words:?}: {stdout}");
        let document = document(&stdout);
        assert_eq!(
            stdout.find("\"phase\""),
            Some(1),
            "{words:?}: `phase` leads the envelope: {stdout}"
        );
        assert_eq!(document["phase"], phase, "{words:?}: {stdout}");
        assert_eq!(document["failure"]["code"], "command_failed", "{stdout}");
        let message = document["failure"]["message"].as_str().unwrap();
        assert!(
            message.starts_with(&format!("{phase}: paths.toml")),
            "{words:?}: {message}"
        );
        assert!(message.contains("paths.core"), "{words:?}: {message}");
        if let ["generate", "exports", target] = words {
            assert_eq!(document["target"], *target, "{words:?}: {stdout}");
        }

        let (code, stderr) = run_plain(&ws, words);
        assert_eq!(code, 1, "{words:?}: {stderr}");
        let lines: Vec<&str> = stderr.lines().collect();
        assert!(
            lines
                .first()
                .is_some_and(|row| row.starts_with(&format!("✗ {step} · "))),
            "{words:?}: the failed row first: {stderr}"
        );
        assert_eq!(
            lines.get(1).copied(),
            Some(format!("error: {message}").as_str()),
            "{words:?}: {stderr}"
        );
        assert_eq!(replay::files(&ws), before, "{words:?}");
    }
}

/// Runs the CLI in-process at `ws` in plain mode; the exit code and stderr.
fn run_plain(ws: &Path, words: &[&str]) -> (i32, String) {
    let sink: Sink = Arc::new(Mutex::new(Buffer::default()));
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let err = Buffer::default();
    let mut out = Vec::new();
    let exit_code = run(&argv, &env, &host, &mut out, &mut err.clone());
    let stderr = String::from_utf8(err.0.lock().unwrap().clone()).unwrap();
    (exit_code, stderr)
}

/// The full pipeline (UC-6.0, #841) names the object files in subfolders it
/// skipped once, after the phases, in the oracle's `nested_object_file`
/// warning (`report_nested_object_files`), its list as Python prints one;
/// with `OPENTIDE_PROGRESS=json`, each phase's event comes before its row.
#[test]
fn the_full_pipeline_names_the_nested_files_it_skipped() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let nested = ws.join("Objects/Detection Objectives/old");
    std::fs::create_dir_all(&nested).unwrap();
    let objective = std::fs::read_dir(ws.join("Objects/Detection Objectives"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .unwrap();
    std::fs::copy(&objective, nested.join("x.yaml")).unwrap();
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.clone()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([
        ("HOME".to_owned(), home.display().to_string()),
        ("OPENTIDE_PROGRESS".to_owned(), "json".to_owned()),
    ]);
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let exit_code = run(&["generate".to_owned()], &env, &host, &mut out, &mut err);
    let stderr = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert_eq!(exit_code, 0, "{stderr}");
    let path = "Objects/Detection Objectives/old/x.yaml";
    let issue = "https://github.com/opentidehq/opentide/issues/584";
    assert!(
        stderr.contains(&format!(
            "warning: Nested object file · detail: 1 object file(s) in subfolders of an object \
             folder are not object instances and are skipped (opentide reads only files \
             directly in each object folder; see {issue}): {path} · count: 1 · files: \
             [\"{path}\"] · issue: {issue}\n"
        )),
        "{stderr}"
    );
    let lines: Vec<&str> = stderr.lines().collect();
    let docs = lines
        .iter()
        .position(|line| *line == r#"{"event":"progress","step":"docs","done":1,"total":6}"#)
        .unwrap_or_else(|| panic!("{stderr}"));
    assert!(lines[docs + 1].starts_with("✓ docs · "), "{stderr}");
    assert!(
        stderr.contains(r#"{"event":"progress","step":"snippets","done":6,"total":6}"#),
        "{stderr}"
    );
}
