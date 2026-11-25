//! Dynamic shell completion end to end: the binary run as a shell's
//! registration runs it on a Tab press, `_OPENTIDE_COMPLETE` naming the
//! shell and the command line after `--`, on the CLI end-to-end corpus
//! (`tests/fixtures/tide_corpus/current`). Only the candidates reach stdout.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a binary that does not start is a failure"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Copies `from` into `to`.
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

/// The corpus in the `.opentide/` layout, its objects in the default folders.
fn corpus(root: &Path) -> PathBuf {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tide_corpus/current");
    let ws = root.join("ws");
    copy_tree(
        &source.join("Configurations"),
        &ws.join(".opentide/configurations"),
    );
    for (family, folder) in [
        ("threats", "Threat Vectors"),
        ("objectives", "Detection Objectives"),
        ("rules", "Detection Rules"),
    ] {
        copy_tree(
            &source.join("Objects").join(folder),
            &ws.join("objects").join(family),
        );
    }
    ws
}

/// The binary, in `cwd`, asked by `shell` to complete `words` (the program's
/// name first, the word being completed last).
fn complete(shell: &str, cwd: &Path, words: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_opentide-cli"));
    command
        .current_dir(cwd)
        .arg("--")
        .args(words)
        .env("_OPENTIDE_COMPLETE", shell);
    for name in [
        "OPENTIDE_REPO_ROOT",
        "OPENTIDE_TIDE_WORKSPACE",
        "OPENTIDE_DATA_ROOT",
        "_CLAP_COMPLETE_INDEX",
        "_CLAP_IFS",
    ] {
        command.env_remove(name);
    }
    command.envs(env.iter().copied());
    command.output().unwrap()
}

/// fish's answer: one `value<TAB>help` line per candidate.
fn fish(cwd: &Path, words: &[&str]) -> Vec<(String, String)> {
    let output = complete("fish", cwd, words, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let (value, help) = line.split_once('\t').unwrap_or((line, ""));
            (value.to_owned(), help.to_owned())
        })
        .collect()
}

fn values(found: &[(String, String)]) -> Vec<&str> {
    found.iter().map(|(value, _)| value.as_str()).collect()
}

#[test]
fn completion_uuid_file_and_explain_from_the_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let ws = corpus(dir.path());

    let uuids = fish(&ws, &["opentide", "validate", "--uuid", ""]);
    assert_eq!(uuids.len(), 12, "{uuids:?}");
    assert!(uuids.contains(&(
        "00000000-0000-4000-8003-000000000001".to_owned(),
        "Sentinel KQL Rule (rule)".to_owned()
    )));
    assert!(uuids.contains(&(
        "00000000-0000-4000-8001-000000000001".to_owned(),
        "Simulated Actor (threat)".to_owned()
    )));
    // `validate query` reads rules only; `--type` narrows the rest.
    let rules = fish(&ws, &["opentide", "validate", "query", "--uuid", ""]);
    assert!(rules.iter().all(|(_, help)| help.ends_with("(rule)")));
    let threats = fish(
        &ws,
        &[
            "opentide", "share", "push", "--type", "threat", "--uuid", "",
        ],
    );
    assert_eq!(values(&threats), ["00000000-0000-4000-8001-000000000001"]);
    // `--uuid=` completes its value too.
    let inline = fish(
        &ws,
        &["opentide", "validate", "--uuid=00000000-0000-4000-8001"],
    );
    assert_eq!(
        values(&inline),
        ["--uuid=00000000-0000-4000-8001-000000000001"]
    );

    let files = fish(
        &ws,
        &["opentide", "validate", "--file", "objects/rules/rule-000"],
    );
    assert_eq!(files.len(), 9, "{files:?}");
    assert_eq!(
        files[0],
        (
            "objects/rules/rule-0001-sentinel-kql.yaml".to_owned(),
            "Sentinel KQL Rule".to_owned()
        )
    );
    // From inside a folder, the path is from there; `--repo` places the
    // workspace from anywhere.
    let inside = fish(
        &ws.join("objects").join("threats"),
        &["opentide", "lint", "--file", "thr"],
    );
    assert_eq!(values(&inside), ["threat-0001-simulated-actor.yaml"]);
    let repo = ws.to_string_lossy().into_owned();
    let other = dir.path().join("other");
    std::fs::create_dir(&other).unwrap();
    let elsewhere = fish(
        &other,
        &[
            "opentide",
            "--repo",
            &repo,
            "validate",
            "--file",
            "objects/obj",
        ],
    );
    assert_eq!(
        values(&elsewhere),
        ["objects/objectives/objective-0001-credential-access.yaml"]
    );

    let codes = fish(&ws, &["opentide", "explain", "vocab_unk"]);
    assert_eq!(values(&codes), ["vocab_unknown"]);
    assert!(!codes[0].1.is_empty());

    // Commands, options and choices still come from the tree.
    assert_eq!(values(&fish(&ws, &["opentide", "valid"])), ["validate"]);
    assert!(values(&fish(&ws, &["opentide", "validate", "--fi"])).contains(&"--file"));
    let enabled = fish(&ws, &["opentide", "deploy", "--platform", "sp"]);
    assert_eq!(enabled, [("splunk".to_owned(), "enabled".to_owned())]);
}

#[test]
fn completion_speaks_each_shell_s_protocol() {
    let dir = tempfile::tempdir().unwrap();
    let ws = corpus(dir.path());
    let words = ["opentide", "explain", "vocab_unk"];
    // bash and zsh name the word being completed and the separator.
    let bash = complete(
        "bash",
        &ws,
        &words,
        &[("_CLAP_COMPLETE_INDEX", "2"), ("_CLAP_IFS", "\u{b}")],
    );
    assert_eq!(bash.status.code(), Some(0));
    assert_eq!(String::from_utf8(bash.stdout).unwrap(), "vocab_unknown");
    let zsh = complete(
        "zsh",
        &ws,
        &words,
        &[("_CLAP_COMPLETE_INDEX", "2"), ("_CLAP_IFS", "\n")],
    );
    assert_eq!(zsh.status.code(), Some(0));
    assert!(
        String::from_utf8(zsh.stdout)
            .unwrap()
            .starts_with("vocab_unknown:"),
    );
    let powershell = complete("powershell", &ws, &words, &[]);
    assert!(
        String::from_utf8(powershell.stdout)
            .unwrap()
            .starts_with("vocab_unknown\t"),
    );

    // Without `--`, the shell's registration, as `--show-completion` prints it.
    let registration = Command::new(env!("CARGO_BIN_EXE_opentide-cli"))
        .env("_OPENTIDE_COMPLETE", "zsh")
        .output()
        .unwrap();
    assert_eq!(registration.status.code(), Some(0));
    assert!(
        String::from_utf8(registration.stdout)
            .unwrap()
            .starts_with("#compdef opentide")
    );

    // A shell it does not know is an error on stderr, nothing on stdout.
    let unknown = complete("tcsh", &ws, &words, &[]);
    assert_ne!(unknown.status.code(), Some(0));
    assert!(unknown.stdout.is_empty());
}

#[test]
fn completion_in_an_empty_folder_completes_no_workspace_value() {
    let dir = tempfile::tempdir().unwrap();
    assert!(fish(dir.path(), &["opentide", "validate", "--uuid", ""]).is_empty());
    let platforms = fish(dir.path(), &["opentide", "deploy", "--platform", ""]);
    assert!(platforms.iter().all(|(_, help)| help.is_empty()));
    assert!(values(&platforms).contains(&"sentinel"));
}
