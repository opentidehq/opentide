//! Behaviour of the commands of UC-3.5 (#827) that the snapshot suite
//! (`cli_snapshots.rs`) does not hold: `--watch`, the dry-run filter, `new`'s
//! references, and the length of a case root. What each command prints and
//! writes is held by `cli_snapshots`.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken recording is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

/// A case's root is named and placed as the retired `cargo xtask golden
/// check` placed it (`/tmp/golden-XXXXXX`): a frame wraps a message by the
/// length of the path in it, so a root of another length (`tempfile`'s
/// `.tmpXXXXXX`) let a replay pass where the real compare differed. Where
/// `/tmp` is a link to a longer folder (macOS), the name is shortened to
/// keep the canonical root, the path the replay reads, that length.
#[test]
fn a_case_root_is_as_long_as_the_golden_checks() {
    let root = replay::case_root();
    let name = root.path().file_name().unwrap().to_str().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    let (prefix, random) = replay::root_name(canonical.parent().unwrap());
    assert!(
        name.starts_with(prefix) && name.len() == prefix.len() + random,
        "{name}"
    );
    assert_eq!(root.path().parent().unwrap(), replay::case_root_parent());
    if canonical.parent() == Some(std::path::Path::new("/tmp")) {
        assert_eq!((prefix, random), ("golden-", 6));
    } else if cfg!(unix) {
        assert_eq!(
            canonical.as_os_str().len(),
            "/tmp/golden-XXXXXX".len(),
            "{}",
            canonical.display()
        );
    }
}

/// `validate --watch` in `plain` mode: one pass's frames and outcome line,
/// then Ctrl-C (already pressed here) stops it with exit 0 and nothing on
/// stderr.
#[test]
fn a_watch_shows_a_pass_and_ctrl_c_exits_0() {
    use opentide_cli::env::Env;
    use opentide_cli::logging::Sink;
    use opentide_cli::{Host, run};
    use std::sync::{Arc, Mutex};
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus-typo", &ws);
    let interrupt = opentide_cli::app::Interrupt::default();
    interrupt.request();
    let sink: Sink = Arc::new(Mutex::new(replay::Buffer::default()));
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.clone()),
        width: None,
        interrupt,
    };
    let argv: Vec<String> = ["validate", "--watch"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let env = Env::from_pairs([("HOME".to_owned(), ws.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), replay::Buffer::default());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    let stdout = String::from_utf8(out).unwrap();
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.starts_with("error[vocab_unknown]: \"high\" is not a alert severity value\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("\n✗ 1 error in 1 file · 1 fixable with --fix · 12 objects checked · "),
        "{stdout}"
    );
    assert!(err.0.lock().unwrap().is_empty());
}

/// Runs `words` in-process at `ws` (not a terminal); the exit code and
/// stdout.
fn run_at(ws: &std::path::Path, words: &[&str]) -> (i32, String) {
    use opentide_cli::env::Env;
    use opentide_cli::logging::Sink;
    use opentide_cli::{Host, run};
    use std::sync::{Arc, Mutex};
    let sink: Sink = Arc::new(Mutex::new(replay::Buffer::default()));
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
    let (mut out, mut err) = (Vec::new(), replay::Buffer::default());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap())
}

/// The tide corpus with one rule's `response` on one line, where the
/// misspelt `alert_severity` (a safe fix) and an unknown key (no fix) are
/// two findings on the same line.
fn two_findings_on_one_line() -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    let path = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let block = "response:\n  alert_severity: High\n";
    assert_eq!(text.matches(block).count(), 1);
    std::fs::write(
        &path,
        text.replace(block, "response: {alert_severity: high, bogus: 1}\n"),
    )
    .unwrap();
    (scratch, ws)
}

/// `--fix --dry-run` shows the diff and leaves out the frame of the finding
/// it would fix, and only that one: the other finding on the same line is
/// still shown.
#[test]
fn a_dry_run_hides_the_findings_it_would_fix_and_no_other() {
    let (_scratch, ws) = two_findings_on_one_line();
    let (code, stdout) = run_at(&ws, &["validate", "--fix", "--dry-run"]);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        stdout.contains("\n+response: {alert_severity: High, bogus: 1}\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("error[schema_validation]: response.bogus: Extra inputs are not permitted"),
        "{stdout}"
    );
    assert!(!stdout.contains("error[vocab_unknown]"), "{stdout}");
    // Without --dry-run's diff, both are frames.
    let (_, plain) = run_at(&ws, &["validate"]);
    assert!(plain.contains("error[vocab_unknown]"), "{plain}");
    assert!(plain.contains("error[schema_validation]"), "{plain}");
}

/// A `--file` path that does not exist fails with `file_not_found`, not
/// `scope_no_match`, and the "check again" step keeps the run's scope.
#[test]
fn a_missing_file_is_not_found_and_the_rerun_keeps_the_scope() {
    let scratch = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus-typo", &dir);
    let (code, stdout) = run_at(
        &dir,
        &["--json", "validate", "--file", "does/not/exist.yaml"],
    );
    assert_eq!(code, 1, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let codes: Vec<&str> = document["report"]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, ["file_not_found"], "{stdout}");
    let commands: Vec<&str> = document["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| action["command"].as_str().unwrap())
        .collect();
    assert!(
        commands.contains(&"opentide --json validate --file does/not/exist.yaml"),
        "{commands:?}"
    );
}

/// A run narrowed to objects that do not exist fails with `scope_no_match`;
/// it is not the empty workspace's pass, which suggests `opentide setup`.
#[test]
fn a_scoped_run_that_matches_nothing_is_not_an_empty_workspace() {
    let scratch = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    std::fs::create_dir_all(&dir).unwrap();
    let (code, stdout) = run_at(&dir, &["--json", "validate", "--type", "rule"]);
    assert_eq!(code, 1, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["message"], "Validation failed");
    assert_eq!(document["report"]["issues"][0]["code"], "scope_no_match");
    assert!(!stdout.contains("setup"), "{stdout}");
    // Unscoped, the same folder is a pass that names what it did not find.
    let (code, stdout) = run_at(&dir, &["--json", "validate"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["message"],
        "Validation passed, but no detection objects were found under ./"
    );
    assert_eq!(
        document["next_actions"][0]["command"],
        "opentide --json setup"
    );
}

/// `new rule --objective` takes the UUID of an existing objective in any
/// case: the catalogue's UUIDs are compared in lower case, so an upper-case
/// one is the same object, not `reference_not_found`.
#[test]
fn new_finds_a_reference_whatever_the_case_of_its_uuid() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("vscode", &ws);
    for (uuid, name) in [
        (
            "04149254-2A5B-4C1E-9F0E-3C1D2B5A6E7F",
            "Upper Case Reference",
        ),
        (
            "04149254-2a5b-4c1e-9f0e-3c1d2b5a6e7f",
            "Lower Case Reference",
        ),
    ] {
        let (code, stdout) = run_at(
            &ws,
            &["--json", "new", "rule", "--name", name, "--objective", uuid],
        );
        assert_eq!(code, 0, "{stdout}");
        let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(document["ok"], true, "{stdout}");
    }
    // An objective that is not there is still refused.
    let (code, stdout) = run_at(
        &ws,
        &[
            "--json",
            "new",
            "rule",
            "--name",
            "Missing",
            "--objective",
            "04149254-2A5B-4C1E-9F0E-3C1D2B5A6E70",
        ],
    );
    assert_eq!(code, 2, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["failure"]["code"], "reference_not_found");
}

/// A name that is empty or only spaces is an invalid `--name`, not a
/// missing one (#1670, smoke B8): `new` did say it "prompts only at an
/// interactive terminal", whatever the terminal.
#[test]
fn new_refuses_an_empty_name_as_an_invalid_value() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    for name in ["", "   "] {
        let (code, stdout) = run_at(&ws, &["--json", "new", "threat", "--name", name]);
        assert_eq!(code, 2, "{stdout}");
        let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            document["failure"]["code"], "usage_invalid_value",
            "{stdout}"
        );
        assert_eq!(document["failure"]["argument"], "--name", "{stdout}");
        assert_eq!(
            document["failure"]["message"], "--name cannot be empty",
            "{stdout}"
        );
    }
    // No --name at all, and no terminal to ask at: still a missing input.
    let (code, stdout) = run_at(&ws, &["--json", "new", "threat"]);
    assert_eq!(code, 2, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["failure"]["code"], "usage_needs_input", "{stdout}");
}

/// `setup --name` is trimmed, and a name that is empty or only spaces is an
/// invalid `--name`, as it is for `new` (#1729, E2E-2): `setup --name "   "`
/// wrote a README headed `#    `. Leaving `--name` out keeps the folder name.
#[test]
fn setup_trims_the_name_and_refuses_an_empty_one() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let readme = |folder: &str| {
        let text = std::fs::read_to_string(ws.join(folder).join("README.md")).unwrap();
        text.lines().next().unwrap().to_owned()
    };
    for (command, line) in [
        ("setup", &["--json", "setup", "--yes", "--path", "none"][..]),
        (
            "setup repo",
            &["--json", "setup", "repo", "--yes", "--path", "none"][..],
        ),
    ] {
        for name in ["", "   "] {
            let (code, stdout) = run_at(&ws, &[line, &["--name", name]].concat());
            assert_eq!(code, 2, "{command} {name:?}: {stdout}");
            let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(document["command"], command, "{stdout}");
            assert_eq!(
                document["failure"]["code"], "usage_invalid_value",
                "{stdout}"
            );
            assert_eq!(document["failure"]["argument"], "--name", "{stdout}");
            assert_eq!(
                document["failure"]["message"], "--name cannot be empty",
                "{stdout}"
            );
        }
    }
    // Nothing was written by the refusals.
    assert!(!ws.join("none").exists());
    // A name is kept without its surrounding spaces, in the README and the
    // document.
    let (code, stdout) = run_at(
        &ws,
        &[
            "--json", "setup", "--yes", "--path", "trimmed", "--name", "  Mine  ",
        ],
    );
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(readme("trimmed"), "# Mine");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let steps = document["steps"].as_array().unwrap();
    let scaffold = steps
        .iter()
        .find(|step| step["scaffolded"] == true)
        .unwrap();
    assert_eq!(scaffold["name"], "Mine", "{stdout}");
    // No `--name` keeps the folder name.
    let (code, stdout) = run_at(&ws, &["--json", "setup", "--yes", "--path", "folder"]);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(readme("folder"), "# folder");
}

/// `setup skills` and `--org` follow `--name`'s rule (#1729): empty or only
/// spaces is `usage_invalid_value`, refused before any request for the skills
/// catalogue.
#[test]
fn setup_refuses_an_empty_org_and_an_empty_skills_name() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    for (command, flag, line) in [
        (
            "setup skills",
            "--name",
            &[
                "--json",
                "setup",
                "skills",
                "--yes",
                "--generic",
                "--path",
                "none",
            ][..],
        ),
        (
            "setup skills",
            "--org",
            &[
                "--json",
                "setup",
                "skills",
                "--yes",
                "--generic",
                "--path",
                "none",
            ][..],
        ),
        (
            "setup",
            "--org",
            &["--json", "setup", "--yes", "--path", "none"][..],
        ),
        (
            "setup repo",
            "--org",
            &["--json", "setup", "repo", "--yes", "--path", "none"][..],
        ),
    ] {
        for value in ["", "   "] {
            let (code, stdout) = run_at(&ws, &[line, &[flag, value]].concat());
            assert_eq!(code, 2, "{command} {flag} {value:?}: {stdout}");
            let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(document["command"], command, "{stdout}");
            assert_eq!(
                document["failure"]["code"], "usage_invalid_value",
                "{stdout}"
            );
            assert_eq!(document["failure"]["argument"], flag, "{stdout}");
            assert_eq!(
                document["failure"]["message"],
                format!("{flag} cannot be empty"),
                "{stdout}"
            );
        }
    }
    // Nothing was written by the refusals.
    assert!(!ws.join("none").exists());
}

/// A repeated `--platform` is a usage error naming the flag, not the last
/// value alone (#1729, E2E-5): `deploy --platform elastic --platform splunk`
/// planned only `splunk`.
#[test]
fn a_repeated_platform_is_a_usage_error() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    let (code, stdout) = run_at(
        &ws,
        &[
            "--json",
            "deploy",
            "--dry-run",
            "--strategy",
            "PREVIEW",
            "--all",
            "--platform",
            "elastic",
            "--platform",
            "splunk",
        ],
    );
    assert_eq!(code, 2, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["ok"], false, "{stdout}");
    assert_eq!(document["failure"]["code"], "usage_error", "{stdout}");
    assert_eq!(document["failure"]["argument"], "--platform", "{stdout}");
    let message = document["failure"]["message"].as_str().unwrap();
    assert!(message.contains("--platform"), "{stdout}");
    assert!(
        message.contains("cannot be used multiple times"),
        "{stdout}"
    );
}

/// `new --path` into a folder below the family's, or outside the
/// workspace, writes a file opentide does not read (#1670, smoke B7): it
/// says so, and does not point at a `validate --file` that refuses it.
#[test]
fn new_warns_when_the_path_is_outside_the_family_folder() {
    let scratch = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    let ws = root.join("ws");
    replay::fixture("empty", &ws);
    let elsewhere = root.join("elsewhere.yaml");
    for (name, path) in [
        ("Sub Dir", "objects/threats/team-a/".to_owned()),
        ("Elsewhere", elsewhere.display().to_string()),
    ] {
        let (code, stdout) = run_at(
            &ws,
            &["--json", "new", "threat", "--name", name, "--path", &path],
        );
        assert_eq!(code, 0, "{stdout}");
        let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let warnings = document["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .any(|warning| warning.as_str().unwrap().contains(
                    "is not directly in objects/threats/, so opentide will not index, validate"
                )),
            "{stdout}"
        );
        assert!(!stdout.contains("validate --file"), "{stdout}");
    }
    // The family's folder itself, named by --path: no such warning.
    let (code, stdout) = run_at(
        &ws,
        &[
            "--json",
            "new",
            "threat",
            "--name",
            "In Place",
            "--path",
            "objects/threats/",
        ],
    );
    assert_eq!(code, 0, "{stdout}");
    assert!(!stdout.contains("is not directly in"), "{stdout}");
    assert!(stdout.contains("validate --file"), "{stdout}");
}

/// `new` warns when the file it wrote does not match the `lint.toml`
/// `[filenames]` pattern (the kind's own table first), naming the key, and
/// not when it does.
#[test]
fn new_warns_when_the_file_breaks_the_lint_filename_pattern() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    let lint = ws.join(".opentide/configurations/lint.toml");
    std::fs::write(
        &lint,
        "[filenames]\npattern = \"rule-.*\"\n\n[filenames.threats]\npattern = \"tv-.*\"\n",
    )
    .unwrap();
    let (code, stdout) = run_at(
        &ws,
        &["--json", "new", "threat", "--name", "Credential Dumping"],
    );
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["warnings"][0],
        "credential-dumping.yaml does not match lint.toml [filenames.threats].pattern tv-.*; \
         rename it before opentide lint runs",
        "{stdout}"
    );
    // A name the pattern takes: no warning.
    let (code, stdout) = run_at(&ws, &["--json", "new", "threat", "--name", "TV Dumping"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let warnings = document["warnings"].as_array().unwrap();
    assert!(!warnings.is_empty(), "{stdout}");
    assert!(
        warnings.iter().all(|warning| !warning
            .as_str()
            .unwrap()
            .contains("does not match lint.toml")),
        "{stdout}"
    );
}

#[test]
fn a_case_root_keeps_the_recorded_length_behind_a_longer_tmp() {
    use std::path::Path;
    // Linux's `/tmp`: the name the retired `cargo xtask golden check` gave.
    assert_eq!(replay::root_name(Path::new("/tmp")), ("golden-", 6));
    // macOS's `/tmp` is `/private/tmp`: `/private/tmp/goXXX` is as long as
    // `/tmp/golden-XXXXXX`, so paths wrap where the recordings wrap.
    let (prefix, random) = replay::root_name(Path::new("/private/tmp"));
    assert_eq!(
        "/private/tmp/".len() + prefix.len() + random,
        "/tmp/golden-XXXXXX".len()
    );
    assert!(random >= 3);
    // No room for three random characters: the recorded name, as before.
    assert_eq!(
        replay::root_name(Path::new("/a/very/long/temporary/folder")),
        ("golden-", 6)
    );
}
