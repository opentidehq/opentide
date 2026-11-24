//! `opentide setup vscode` stays a working alternative, and says the opentide
//! VS Code extension is the recommended way: a `note:` with the install
//! command in human mode, never a deprecation warning, and none of it in
//! `--json`'s result.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a binary that does not start is a failure"
)]

use std::process::{Command, Output};

fn setup_vscode(args: &[&str]) -> (Output, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_opentide-cli"))
        .args(["setup", "vscode", "--settings", "--no-generate", "--yes"])
        .args(args)
        .arg("-C")
        .arg(dir.path())
        .env_clear()
        .output()
        .unwrap();
    (output, dir)
}

#[test]
fn the_human_output_recommends_the_extension_without_deprecating_the_command() {
    let (output, dir) = setup_vscode(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("code --install-extension opentidehq.opentide"),
        "{stderr}"
    );
    assert!(stderr.contains("note:"), "{stderr}");
    assert!(!stderr.to_lowercase().contains("deprecated"), "{stderr}");
    assert!(!stderr.contains("warning:"), "{stderr}");
    // The command still does its work.
    assert!(dir.path().join(".vscode/extensions.json").is_file());
}

#[test]
fn the_json_result_does_not_call_the_command_deprecated() {
    let (output, _dir) = setup_vscode(&["--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["ok"], true, "{stdout}");
    assert!(result.get("deprecated").is_none(), "{stdout}");
    assert!(!stdout.to_lowercase().contains("deprecated"), "{stdout}");
}
