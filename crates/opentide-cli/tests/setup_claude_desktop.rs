//! `opentide setup mcp --claude-desktop` (#1036), end to end: the binary
//! run with every folder Claude Desktop's configuration can live in (`HOME`,
//! `USERPROFILE`, `APPDATA`, `XDG_CONFIG_HOME`) pointed at temporary ones,
//! and `PATH` at a stand-in `opentide`. Not a snapshot case: the file is in
//! a different place on each system, and the snapshots run on all three.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a binary that does not start is a failure"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use opentide_cli::commands::setup::desktop::{Os, config_path};
use opentide_cli::env::Env;
use serde_json::Value;

struct Machine {
    _dir: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    bin: PathBuf,
}

impl Machine {
    fn new() -> Machine {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("home é😀");
        let workspace = root.join("detections é😀");
        let bin = root.join("bin");
        for folder in [&home, &workspace, &bin] {
            std::fs::create_dir_all(folder).unwrap();
        }
        std::fs::create_dir_all(workspace.join(".opentide")).unwrap();
        let opentide = bin.join("opentide");
        std::fs::write(&opentide, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&opentide, std::fs::Permissions::from_mode(0o755)).unwrap();
        Machine {
            _dir: dir,
            home,
            workspace,
            bin,
        }
    }

    fn vars(&self) -> Vec<(&'static str, String)> {
        self.vars_with_path(&self.bin.to_string_lossy())
    }

    fn vars_with_path(&self, path: &str) -> Vec<(&'static str, String)> {
        let home = self.home.to_string_lossy().into_owned();
        vec![
            ("HOME", home.clone()),
            ("USERPROFILE", home.clone()),
            ("APPDATA", format!("{home}/AppData/Roaming")),
            ("XDG_CONFIG_HOME", format!("{home}/.config")),
            ("PATH", path.to_owned()),
        ]
    }

    /// Where Claude Desktop reads its configuration on this system.
    fn config(&self) -> PathBuf {
        let env = Env::from_pairs(self.vars());
        config_path(Os::current(), &env, Some(&self.home)).unwrap()
    }

    fn run(&self, args: &[&str]) -> (i32, Value) {
        self.run_as(args, &self.bin.to_string_lossy(), None)
    }

    /// `args` run with `PATH` set to `path`, and started as `argv0` (the
    /// console script's interpreter) when given.
    fn run_as(&self, args: &[&str], path: &str, argv0: Option<&Path>) -> (i32, Value) {
        use std::os::unix::process::CommandExt as _;
        let mut command = Command::new(env!("CARGO_BIN_EXE_opentide-cli"));
        if let Some(argv0) = argv0 {
            command.arg0(argv0);
        }
        let output = command
            .arg("--json")
            .args(args)
            .current_dir(&self.workspace)
            .env_clear()
            .envs(self.vars_with_path(path))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!(
                "{error}: {stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code().unwrap(), value)
    }

    /// Every file under the home folder, with its bytes.
    fn home_files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(folder: &Path, found: &mut Vec<(PathBuf, Vec<u8>)>) {
            for entry in std::fs::read_dir(folder).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, found);
                } else {
                    found.push((path.clone(), std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut found = Vec::new();
        walk(&self.home, &mut found);
        found.sort();
        found
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_server_is_merged_into_the_users_file_and_doctor_counts_it() {
    let machine = Machine::new();
    let config = machine.config();
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "{\n  \"globalShortcut\": \"é😀\",\n  \"mcpServers\": {\n    \"other\": {\"command\": \"/bin/other\", \"args\": []}\n  }\n}\n",
    )
    .unwrap();
    let (code, result) = machine.run(&["setup", "mcp", "--claude-desktop", "--yes"]);
    assert_eq!(code, 0, "{result}");
    let shown = config.to_string_lossy().into_owned();
    assert_eq!(
        strings(&result["files"]),
        std::slice::from_ref(&shown),
        "{result}"
    );
    assert_eq!(result["claude_desktop_config"], shown.as_str());
    assert!(
        result["advice"]
            .as_str()
            .unwrap()
            .contains("Claude Desktop"),
        "{result}"
    );
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    assert_eq!(written["globalShortcut"], "é😀");
    assert_eq!(written["mcpServers"]["other"]["command"], "/bin/other");
    let server = &written["mcpServers"]["opentide"];
    assert_eq!(
        server["command"],
        machine.bin.join("opentide").to_string_lossy().as_ref()
    );
    assert_eq!(server["args"], serde_json::json!(["mcp", "start"]));
    assert_eq!(
        server["env"]["OPENTIDE_REPO_ROOT"],
        machine.workspace.to_string_lossy().as_ref()
    );

    let (_, doctor) = machine.run(&["doctor", "--offline"]);
    let check = doctor["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["code"] == "mcp_config")
        .unwrap_or_else(|| panic!("{doctor}"))
        .clone();
    assert_eq!(check["status"], "pass", "{check}");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("MCP configured for Claude Desktop"),
        "{check}"
    );
}

/// The case the host exists for: `opentide` is not on `PATH` (a virtual
/// environment that is not activated), and the entry names it by its path,
/// so the server is available and nothing warns about `PATH`.
#[test]
fn opentide_off_path_is_named_by_its_path_and_available() {
    use std::os::unix::fs::PermissionsExt as _;
    let machine = Machine::new();
    let venv = machine.home.join("venv é😀").join("bin");
    std::fs::create_dir_all(&venv).unwrap();
    let script = venv.join("opentide");
    std::fs::write(&script, "#!/usr/bin/python3\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let empty = machine.home.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let (code, result) = machine.run_as(
        &["setup", "mcp", "--claude-desktop", "--yes"],
        &empty.to_string_lossy(),
        Some(&venv.join("python3")),
    );
    assert_eq!(code, 0, "{result}");
    assert_eq!(result["mcp_available"], true, "{result}");
    assert!(strings(&result["warnings"]).is_empty(), "{result}");
    let written: Value =
        serde_json::from_str(&std::fs::read_to_string(machine.config()).unwrap()).unwrap();
    assert_eq!(
        written["mcpServers"]["opentide"]["command"],
        script.to_string_lossy().as_ref()
    );
    // Another host still runs a bare `opentide`, which needs PATH.
    let (_, result) = machine.run_as(
        &["setup", "mcp", "--claude-desktop", "--cursor", "--yes"],
        &empty.to_string_lossy(),
        Some(&venv.join("python3")),
    );
    assert_eq!(result["mcp_available"], false, "{result}");
    assert!(
        result.to_string().contains("opentide is not on PATH"),
        "{result}"
    );
}

#[test]
fn a_plan_lists_the_file_by_its_path_and_writes_nothing_there() {
    let machine = Machine::new();
    let before = machine.home_files();
    let shown = machine.config().to_string_lossy().into_owned();
    for args in [
        &["setup", "mcp", "--claude-desktop", "--plan"][..],
        &["setup", "--plan", "--mcp", "claude-desktop"][..],
    ] {
        let (code, result) = machine.run(args);
        assert_eq!(code, 0, "{args:?}: {result}");
        let listed = result.to_string();
        assert!(
            listed.contains(&serde_json::to_string(&shown).unwrap()),
            "{args:?}: {listed}"
        );
        assert!(listed.contains("\"create\""), "{args:?}: {listed}");
        assert_eq!(machine.home_files(), before, "{args:?}");
    }
}

#[test]
fn a_file_that_is_not_json_is_left_alone_with_a_warning() {
    let machine = Machine::new();
    let config = machine.config();
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "{ \"mcpServers\": é😀").unwrap();
    let (code, result) = machine.run(&["setup", "mcp", "--claude-desktop", "--yes"]);
    assert_eq!(code, 0, "{result}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "{ \"mcpServers\": é😀"
    );
    let shown = config.to_string_lossy().into_owned();
    assert_eq!(strings(&result["skipped"]), std::slice::from_ref(&shown));
    let warnings = result.to_string();
    assert!(warnings.contains("is not valid JSON"), "{warnings}");
}

#[test]
fn a_folder_that_cannot_be_written_is_a_warning() {
    let machine = Machine::new();
    let config = machine.config();
    // `Claude` is a file: no folder can be made there, even by root.
    std::fs::create_dir_all(config.parent().unwrap().parent().unwrap()).unwrap();
    std::fs::write(config.parent().unwrap(), "").unwrap();
    let (code, result) = machine.run(&["setup", "mcp", "--claude-desktop", "--vscode", "--yes"]);
    assert_eq!(code, 0, "{result}");
    let shown = config.to_string_lossy().into_owned();
    assert_eq!(strings(&result["files"]), [".vscode/mcp.json"], "{result}");
    assert_eq!(
        strings(&result["skipped"]),
        std::slice::from_ref(&shown),
        "{result}"
    );
    assert!(
        result
            .to_string()
            .contains(&format!("Could not write {shown}")),
        "{result}"
    );
    assert!(machine.workspace.join(".vscode/mcp.json").is_file());
    assert!(!config.exists());
    assert!(result.get("claude_desktop_config").is_none(), "{result}");
    assert!(result.get("advice").is_none(), "{result}");
}

#[test]
fn the_group_writes_it_with_mcp_claude_desktop() {
    let machine = Machine::new();
    let (code, result) = machine.run(&["setup", "--yes", "--mcp", "claude-desktop"]);
    assert_eq!(code, 0, "{result}");
    assert!(machine.config().is_file(), "{result}");
}
