//! `opentide deploy --dry-run` on the Rust command line (UC-3.1c, #896),
//! run in-process through [`opentide_cli::run`] over a workspace on disk:
//! the plan view, the frames of the rules that would fail, the tally, the
//! warnings, the closing note, the JSON document's keys and their order,
//! the progress events, the CI summary, and the refusals.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here is written to a fresh folder"
)]

use opentide_cli::env::Env;
use opentide_cli::json::Json;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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

struct Ran {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

const BAD: &str = "00000000-0000-4000-8000-0000000000b1";
const GOOD: &str = "00000000-0000-4000-8000-0000000000b2";

fn rule(uuid: &str, platform: &str, extra: &str) -> String {
    format!(
        "name: Rule {}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\ndescription: d\n\
         configurations:\n  {platform}:\n    status: STAGING\n{extra}",
        &uuid[uuid.len() - 2..]
    )
}

const SYSDIG: &str = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"one\"\n\
    description = \"d\"\n[tenants.setup]\nssl = true\nurl = \"https://s.example.org\"\n\
    api_token = \"$SYSDIG_TOKEN\"\n";

/// A fresh workspace: Sysdig with one tenant, a rule that compiles and one
/// that cannot (`priority: urgent`).
fn workspace() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "opentide-cli-deploy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    let write = |path: &str, text: &str| {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write(".opentide/configurations/platforms/sysdig.toml", SYSDIG);
    write(
        "objects/rules/bad.yaml",
        &rule(
            BAD,
            "sysdig",
            "    condition: proc.name = x\n    priority: urgent\n",
        ),
    );
    write(
        "objects/rules/good.yaml",
        &rule(GOOD, "sysdig", "    condition: proc.name = y\n"),
    );
    root
}

fn deploy(ws: &Path, args: &[&str], env: &[(&str, String)]) -> Ran {
    let words: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let env = Env::from_pairs(
        env.iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone())),
    );
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let exit_code = run(&words, &env, &host, &mut out, &mut err);
    let stderr = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    Ran {
        exit_code,
        stdout: String::from_utf8(out).unwrap(),
        stderr,
    }
}

fn keys(document: &Json) -> Vec<String> {
    match document {
        Json::Object(members) => members.iter().map(|(key, _)| key.clone()).collect(),
        _ => Vec::new(),
    }
}

#[test]
fn a_dry_run_prints_the_plan_the_failing_rule_the_tally_and_the_note() {
    let ws = workspace();
    let ran = deploy(
        &ws,
        &["deploy", "--strategy", "PREVIEW", "--all", "--dry-run"],
        &[],
    );
    assert_eq!(ran.exit_code, 1, "{}{}", ran.stdout, ran.stderr);
    assert_eq!(
        ran.stdout,
        "Deploy plan · strategy PREVIEW · 1 platform, 1 tenant · dry run, nothing is sent\n\
         \n\
         sysdig · 1 tenant\n  \
           one\n    \
             ✗ would fail  Rule b1  …0000000000b1  status STAGING\n    \
             + create      Rule b2  …0000000000b2  status STAGING\n\
         \n\
         Plan: 1 to create, 0 to update, 0 to disable, 0 to delete, 1 would fail\n\
         dry run, nothing sent\n"
    );
    // The frame names the rule's file; the unset variable is a warning, not
    // an error, on a dry run. The tally is a plan's, on stdout, though the
    // run fails.
    assert_eq!(
        ran.stderr,
        "error[compile_failed]: Sysdig cannot compile this rule: \"URGENT\"\n  \
         ╰─▶ objects/rules/bad.yaml\n\
         \n\
         warning: a real deploy would need $SYSDIG_TOKEN, which is unset\n"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn quiet_keeps_the_frames_and_the_tally_and_drops_the_plan_and_the_note() {
    let ws = workspace();
    let ran = deploy(
        &ws,
        &[
            "--quiet",
            "deploy",
            "--strategy",
            "PREVIEW",
            "--all",
            "--dry-run",
        ],
        &[],
    );
    assert_eq!(ran.exit_code, 1);
    assert_eq!(
        ran.stdout,
        "Plan: 1 to create, 0 to update, 0 to disable, 0 to delete, 1 would fail\n"
    );
    assert!(
        ran.stderr.starts_with("error[compile_failed]"),
        "{}",
        ran.stderr
    );
    assert!(!ran.stderr.contains("warning:"), "{}", ran.stderr);
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn the_json_document_keeps_the_oracles_keys_and_order() {
    let ws = workspace();
    let ran = deploy(
        &ws,
        &[
            "--json",
            "deploy",
            "--strategy",
            "PREVIEW",
            "--all",
            "--dry-run",
        ],
        &[("SYSDIG_TOKEN", "set".to_owned())],
    );
    assert_eq!(ran.exit_code, 1);
    let document = Json::parse(&ran.stdout).unwrap();
    assert_eq!(
        keys(&document),
        [
            "deployed",
            "dry_run",
            "plan",
            "changes",
            "diagnostics",
            "error",
            "strategies",
            "payloads",
            "tenants",
            "ok",
            "status",
            "message",
            "schema_version",
            "command",
            "duration_ms",
            "exit_code",
            "summary",
            "next_actions",
            "failure",
        ]
    );
    assert_eq!(
        document.get("error"),
        Some(&Json::str("1 rule would fail to deploy"))
    );
    let failure = document.get("failure").unwrap();
    assert_eq!(failure.get("code"), Some(&Json::str("command_failed")));
    assert_eq!(
        failure.get("message"),
        Some(&Json::str("1 rule would fail to deploy"))
    );
    assert_eq!(document.get("command"), Some(&Json::str("deploy")));
    assert_eq!(
        keys(document.get("summary").unwrap()),
        [
            "create",
            "update",
            "upsert",
            "disable",
            "delete",
            "platforms",
            "tenants",
            "fail"
        ]
    );
    // Set, so no warning: no `warnings` key at all.
    assert_eq!(ran.stderr, "");
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_failed_selection_puts_error_right_after_the_message() {
    let ws = workspace();
    std::fs::create_dir_all(ws.join("objects/rules/nested")).unwrap();
    std::fs::write(
        ws.join("objects/rules/nested/deep.yaml"),
        rule("00000000-0000-4000-8000-0000000000c1", "sysdig", ""),
    )
    .unwrap();
    let ran = deploy(
        &ws,
        &[
            "--json",
            "deploy",
            "--strategy",
            "PREVIEW",
            "--uuid",
            "00000000-0000-4000-8000-00000000ffff",
            "--dry-run",
        ],
        &[],
    );
    assert_eq!(ran.exit_code, 1);
    let document = Json::parse(&ran.stdout).unwrap();
    let order = keys(&document);
    let at = |key: &str| order.iter().position(|name| name == key).unwrap();
    // No warnings here: `error` comes right after `message`, before every
    // key of the envelope.
    assert!(!order.iter().any(|key| key == "warnings"), "{order:?}");
    assert_eq!(at("message") + 1, at("error"), "{order:?}");
    assert!(at("error") < at("schema_version"), "{order:?}");
    assert_eq!(document.get("scope"), Some(&Json::str("selected")));
    assert_eq!(at("scope"), 0, "{order:?}");
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_failed_plan_puts_error_right_after_the_warnings() {
    let ws = workspace();
    // A selected rule with no `name` fails the plan; an object file the
    // index cannot read is a warning on it.
    std::fs::write(
        ws.join("objects/rules/nameless.yaml"),
        "metadata:\n  uuid: 00000000-0000-4000-8000-0000000000c2\n  schema: rule::1.0\n\
         configurations:\n  sysdig:\n    status: STAGING\n    condition: proc.name = z\n",
    )
    .unwrap();
    std::fs::write(ws.join("objects/rules/broken.yaml"), "name: [unclosed\n").unwrap();
    let ran = deploy(
        &ws,
        &[
            "--json",
            "deploy",
            "--strategy",
            "PREVIEW",
            "--file",
            "objects/rules/nameless.yaml",
            "--dry-run",
        ],
        &[],
    );
    assert_eq!(ran.exit_code, 1, "{}", ran.stdout);
    let document = Json::parse(&ran.stdout).unwrap();
    let order = keys(&document);
    let at = |key: &str| {
        order
            .iter()
            .position(|name| name == key)
            .unwrap_or_else(|| panic!("no {key}: {order:?}"))
    };
    assert_eq!(at("message") + 1, at("warnings"), "{order:?}");
    assert_eq!(at("warnings") + 1, at("error"), "{order:?}");
    assert!(at("error") < at("schema_version"), "{order:?}");
    assert!(at("error") < at("failure"), "{order:?}");
    assert_eq!(document.get("scope"), Some(&Json::str("selected")));
    let _ = std::fs::remove_dir_all(&ws);
}

/// `--json deploy --strategy RELEASE --all --dry-run` run from `cwd`.
fn release_all(cwd: &Path) -> Ran {
    deploy(
        cwd,
        &[
            "--json",
            "deploy",
            "--strategy",
            "RELEASE",
            "--all",
            "--dry-run",
        ],
        &[],
    )
}

#[test]
fn a_skipped_run_at_the_workspace_root_has_no_next_actions() {
    let ws = workspace();
    let ran = release_all(&ws);
    assert_eq!(ran.exit_code, 0, "{}", ran.stdout);
    let document = Json::parse(&ran.stdout).unwrap();
    assert_eq!(document.get("status"), Some(&Json::str("skipped")));
    assert_eq!(document.get("next_actions"), Some(&Json::Array(Vec::new())));
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_skipped_run_outside_a_workspace_names_opentide_setup() {
    // A sibling of a fresh workspace: no workspace above it.
    let ws = workspace();
    let outside = ws.with_extension("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let ran = release_all(&outside);
    assert_eq!(ran.exit_code, 0, "{}", ran.stdout);
    let document = Json::parse(&ran.stdout).unwrap();
    assert_eq!(document.get("status"), Some(&Json::str("skipped")));
    let Some(Json::Array(actions)) = document.get("next_actions") else {
        panic!("no next_actions: {}", ran.stdout);
    };
    assert_eq!(actions.len(), 1, "{}", ran.stdout);
    assert_eq!(
        actions[0].get("command"),
        Some(&Json::str("opentide --json setup"))
    );
    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn progress_events_name_each_platform_compiled() {
    let ws = workspace();
    let ran = deploy(
        &ws,
        &[
            "--json",
            "deploy",
            "--strategy",
            "PREVIEW",
            "--all",
            "--dry-run",
        ],
        &[("OPENTIDE_PROGRESS", "json".to_owned())],
    );
    assert_eq!(
        ran.stderr.lines().next(),
        Some(r#"{"event":"progress","step":"sysdig","done":1,"total":1}"#)
    );
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn the_gitlab_job_summary_names_the_plan() {
    let ws = workspace();
    let ran = deploy(
        &ws,
        &["deploy", "--strategy", "PREVIEW", "--all", "--dry-run"],
        &[
            ("GITLAB_CI", "true".to_owned()),
            ("CI_PROJECT_DIR", ws.display().to_string()),
        ],
    );
    assert_eq!(ran.exit_code, 1);
    let summary = std::fs::read_to_string(ws.join("opentide-reports/summary.md")).unwrap();
    assert!(
        summary.starts_with("### ✗ opentide deploy --dry-run\n"),
        "{summary}"
    );
    assert!(summary.contains("| `sysdig` | one | 2 |"), "{summary}");
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_typo_in_the_strategy_is_the_commands_usage_error_and_writes_no_summary() {
    let ws = workspace();
    let ran = deploy(
        &ws,
        &["--json", "deploy", "--strategy", "PREVEW", "--dry-run"],
        &[
            ("GITLAB_CI", "true".to_owned()),
            ("CI_PROJECT_DIR", ws.display().to_string()),
        ],
    );
    assert_eq!(ran.exit_code, 2);
    let document = Json::parse(&ran.stdout).unwrap();
    let failure = document.get("failure").unwrap();
    assert_eq!(
        failure.get("code"),
        Some(&Json::str("usage_invalid_choice"))
    );
    assert_eq!(failure.get("argument"), Some(&Json::str("--strategy")));
    assert_eq!(failure.get("suggestion"), Some(&Json::str("PREVIEW")));
    assert!(!ws.join("opentide-reports").exists());
    // Plain: the error, its suggestion, then the note.
    // The text modes write a CI summary when a CI provider is set: a usage
    // error writes none.
    let plain = deploy(
        &ws,
        &["deploy", "--strategy", "PREVEW", "--dry-run"],
        &[
            ("GITLAB_CI", "true".to_owned()),
            ("CI_PROJECT_DIR", ws.display().to_string()),
        ],
    );
    assert_eq!(plain.exit_code, 2);
    assert_eq!(plain.stdout, "dry run, nothing sent\n");
    assert!(!ws.join("opentide-reports/summary.md").exists());
    assert!(!ws.join("opentide-reports").exists());
    assert_eq!(
        plain.stderr,
        "error: --strategy \"PREVEW\" is not a deployable strategy. Use PREVIEW or RELEASE\n  \
         help: did you mean 'PREVIEW'?\n"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn all_with_a_selection_is_refused_before_the_run() {
    let ws = workspace();
    let ran = deploy(
        &ws,
        &[
            "--json",
            "deploy",
            "--strategy",
            "PREVIEW",
            "--all",
            "--file",
            "x",
            "--dry-run",
        ],
        &[],
    );
    assert_eq!(ran.exit_code, 2);
    let document = Json::parse(&ran.stdout).unwrap();
    let failure = document.get("failure").unwrap();
    assert_eq!(failure.get("code"), Some(&Json::str("usage_error")));
    assert_eq!(failure.get("argument"), Some(&Json::str("--file")));
    let plain = deploy(
        &ws,
        &[
            "deploy",
            "--strategy",
            "PREVIEW",
            "--all",
            "--uuid",
            "u",
            "--dry-run",
        ],
        &[],
    );
    assert_eq!(plain.exit_code, 2);
    // Refused before the run: no plan and no closing note.
    assert_eq!(plain.stdout, "");
    assert!(
        plain
            .stderr
            .starts_with("error: --all reads every rule file")
    );
    let removed = deploy(
        &ws,
        &["--json", "deploy", "--plan", "staging", "--dry-run"],
        &[],
    );
    assert_eq!(removed.exit_code, 2);
    let failure = Json::parse(&removed.stdout).unwrap();
    let failure = failure.get("failure").unwrap();
    assert_eq!(failure.get("code"), Some(&Json::str("usage_invalid_value")));
    assert_eq!(failure.get("argument"), Some(&Json::str("--plan")));
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_deploy_without_a_platform_sends_to_the_workspaces_platforms() {
    // UC-4.4c (#834): the enabled platforms the plan reaches, here Sysdig,
    // whose unset credential refuses the run before any request.
    let ws = workspace();
    let ran = deploy(
        &ws,
        &["--json", "deploy", "--strategy", "PREVIEW", "--all"],
        &[],
    );
    assert_eq!(ran.exit_code, 1, "{}", ran.stdout);
    let document = Json::parse(&ran.stdout).unwrap();
    assert_eq!(document.get("command"), Some(&Json::str("deploy")));
    let failure = document.get("failure").unwrap();
    assert_ne!(failure.get("code"), Some(&Json::str("engine_not_ported")));
    let plan = document.get("plan").unwrap();
    assert!(plan.get("sysdig").is_some(), "{}", ran.stdout);
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_deploy_without_a_platform_that_matches_no_rule_warns_the_ci_run() {
    let ws = workspace();
    let ci = [("GITHUB_ACTIONS", "true".to_owned())];
    let plain = deploy(&ws, &["deploy", "--strategy", "RELEASE", "--all"], &ci);
    assert_eq!(plain.exit_code, 0, "{}{}", plain.stdout, plain.stderr);
    assert!(
        plain.stdout.starts_with(
            "::warning::No rule this run read has a status that maps to its strategies\n"
        ),
        "{}",
        plain.stdout
    );
    // Not in JSON mode, nor outside CI, nor with --platform.
    let json = deploy(
        &ws,
        &["--json", "deploy", "--strategy", "RELEASE", "--all"],
        &ci,
    );
    assert!(!json.stdout.contains("::warning"), "{}", json.stdout);
    let local = deploy(&ws, &["deploy", "--strategy", "RELEASE", "--all"], &[]);
    assert!(!local.stdout.contains("::warning"), "{}", local.stdout);
    let named = deploy(
        &ws,
        &[
            "deploy",
            "--strategy",
            "RELEASE",
            "--all",
            "--platform",
            "sysdig",
        ],
        &ci,
    );
    assert!(!named.stdout.contains("::warning"), "{}", named.stdout);
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_rule_without_a_status_logs_the_oracles_event_as_json_under_json() {
    let ws = workspace();
    std::fs::write(
        ws.join("objects/rules/good.yaml"),
        "name: No Status\nmetadata:\n  uuid: 00000000-0000-4000-8000-0000000000d1\n  \
         schema: rule::1.0\ndescription: d\nconfigurations:\n  sysdig:\n    condition: x\n",
    )
    .unwrap();
    let ran = deploy(
        &ws,
        &[
            "--json",
            "deploy",
            "--strategy",
            "PREVIEW",
            "--all",
            "--dry-run",
        ],
        &[],
    );
    assert_eq!(ran.exit_code, 1);
    let line = Json::parse(ran.stderr.lines().next().unwrap()).unwrap();
    assert_eq!(
        keys(&line),
        [
            "detail",
            "system",
            "rule",
            "uuid",
            "event",
            "level",
            "timestamp"
        ]
    );
    assert_eq!(
        line.get("event"),
        Some(&Json::str("platform_status_missing"))
    );
    assert_eq!(line.get("system"), Some(&Json::str("sysdig")));
    // The time with its date, `2026-11-10 12:00:00`.
    assert!(
        matches!(line.get("timestamp"), Some(Json::Str(stamp)) if stamp.len() == 19 && stamp.as_bytes()[10] == b' '),
        "{line:?}"
    );
    let plain = deploy(
        &ws,
        &["deploy", "--strategy", "PREVIEW", "--all", "--dry-run"],
        &[],
    );
    assert!(
        plain
            .stderr
            .starts_with("error: Platform status missing · detail: Rule \"No Status\" "),
        "{}",
        plain.stderr
    );
    let _ = std::fs::remove_dir_all(&ws);
}
