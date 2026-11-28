//! `setup mcp --claude-desktop` (#1036): the opentide server in Claude
//! Desktop's own configuration, a file of the user's outside the repository.
//!
//! Claude Desktop's chat does not start the local MCP servers of an
//! installed plugin, expands no placeholder in its configuration and,
//! started from the Dock or the Start menu, does not have the shell's
//! `PATH`. So the entry names `opentide` and the workspace by their absolute
//! paths, and setup merges it into the file the user already has: every
//! other server and setting stays, and in the `opentide` entry setup's own
//! fields are replaced, so running setup from another workspace points
//! Claude Desktop at that one.

use std::path::{Path, PathBuf};

use super::jsonc;
use super::stage::Stage;
use crate::env::Env;
use crate::json::{Json, Object};

/// The host's command-line value: `--mcp claude-desktop`.
pub const HOST: &str = "claude-desktop";

/// The host's name, as `doctor` and the summary print it.
pub const LABEL: &str = "Claude Desktop";

/// The file Claude Desktop reads its MCP servers from.
pub const CONFIG_FILE: &str = "claude_desktop_config.json";

/// The name of the server entry setup writes.
const SERVER: &str = "opentide";

/// What to do once the file is written.
pub const ADVICE: &str = "Quit and reopen Claude Desktop to start the opentide server.";

/// The operating systems whose Claude Desktop keeps its configuration in a
/// different place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
    /// Linux and the rest.
    Other,
}

impl Os {
    /// The system this program runs on.
    pub const fn current() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(windows) {
            Os::Windows
        } else {
            Os::Other
        }
    }
}

/// The user's home folder on `os`: `USERPROFILE` on Windows, `HOME`
/// elsewhere; `None` when it is unset or empty.
pub fn home(os: Os, env: &Env) -> Option<PathBuf> {
    let name = if os == Os::Windows {
        "USERPROFILE"
    } else {
        "HOME"
    };
    env.get(name)
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// Where Claude Desktop on `os` reads its configuration, given the
/// environment and the home folder; `None` when neither tells.
///
/// - macOS: `~/Library/Application Support/Claude/`.
/// - Windows: `%APPDATA%\Claude\`, or `~\AppData\Roaming\Claude\` when
///   `APPDATA` is unset.
/// - Elsewhere: `$XDG_CONFIG_HOME/Claude/`, or `~/.config/Claude/` when the
///   variable is unset or relative (which the XDG specification says to
///   ignore).
pub fn config_path(os: Os, env: &Env, home: Option<&Path>) -> Option<PathBuf> {
    let set = |name: &str| env.get(name).filter(|value| !value.is_empty());
    let folder = match os {
        Os::MacOs => home?.join("Library").join("Application Support"),
        Os::Windows => set("APPDATA")
            .map(PathBuf::from)
            .or_else(|| home.map(|home| home.join("AppData").join("Roaming")))?,
        Os::Other => set("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|folder| folder.is_absolute())
            .or_else(|| home.map(|home| home.join(".config")))?,
    };
    Some(folder.join("Claude").join(CONFIG_FILE))
}

/// The command Claude Desktop runs to start the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    /// The program, an absolute path.
    pub command: PathBuf,
    /// Its arguments.
    pub args: Vec<String>,
}

/// The `opentide` that runs this command, by its absolute path; `None` when
/// none can be found.
///
/// The same `main` runs as a standalone binary, as the PyPI console script
/// (in the Python interpreter, which loads it as a module) and as the npm
/// bin (in Node.js), so this program's own path (`exe`) is `opentide` only
/// in the first case. In order:
///
/// 1. `exe`, when it is an `opentide` binary;
/// 2. an `opentide` beside the program that was started (`argv0`, as typed:
///    the console script's interpreter in its virtual environment, before
///    any link is followed) or beside `exe`: the console script of a
///    virtual environment or of pipx;
/// 3. the `opentide` on `path` (`PATH`), as a shell would find it;
/// 4. `argv0` itself when it is a Python interpreter, with `-m opentide`.
///
/// A script that starts `#!/usr/bin/env NAME` (the npm bin) looks `NAME` up
/// on the `PATH` Claude Desktop does not have: it is run by `exe` when `exe`
/// is `NAME` (Node.js running the npm bin), and passed over otherwise.
pub fn launch(exe: Option<&Path>, argv0: Option<&Path>, path: &str, cwd: &Path) -> Option<Launch> {
    let mcp_start = || vec!["mcp".to_owned(), "start".to_owned()];
    if let Some(exe) = exe.filter(|exe| stem(exe) == "opentide") {
        return Some(Launch {
            command: exe.to_path_buf(),
            args: mcp_start(),
        });
    }
    // How `candidate` starts without the shell's `PATH`, if it can.
    let usable = |candidate: PathBuf| match env_interpreter(&candidate) {
        None => Some(Launch {
            command: candidate,
            args: mcp_start(),
        }),
        Some(name) => exe.filter(|exe| stem(exe) == name).map(|exe| Launch {
            command: exe.to_path_buf(),
            args: std::iter::once(candidate.to_string_lossy().into_owned())
                .chain(mcp_start())
                .collect(),
        }),
    };
    let argv0 = argv0.filter(|argv0| argv0.is_absolute());
    let script = format!("opentide{}", std::env::consts::EXE_SUFFIX);
    let beside = [argv0, exe]
        .into_iter()
        .flatten()
        .filter_map(Path::parent)
        .map(|folder| folder.join(&script))
        .filter(|candidate| candidate.is_file())
        .find_map(usable);
    if beside.is_some() {
        return beside;
    }
    let on_path = crate::commands::doctor::on_path("opentide", path, cwd)
        .map(|found| {
            if found.is_absolute() {
                found
            } else {
                cwd.join(found)
            }
        })
        .and_then(usable);
    if on_path.is_some() {
        return on_path;
    }
    argv0
        .filter(|argv0| stem(argv0).starts_with("python"))
        .map(|python| Launch {
            command: python.to_path_buf(),
            args: ["-m".to_owned(), "opentide".to_owned()]
                .into_iter()
                .chain(mcp_start())
                .collect(),
        })
}

/// The program a script's `#!/usr/bin/env NAME` line names (`node`), which
/// the script looks up on `PATH`; `None` for any other file.
fn env_interpreter(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let mut head = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(256)
        .read_to_end(&mut head)
        .ok()?;
    let line = head
        .strip_prefix(b"#!")?
        .split(|byte| *byte == b'\n')
        .next()?;
    let line = String::from_utf8_lossy(line);
    let mut words = line.split_whitespace();
    if stem(Path::new(words.next()?)) != "env" {
        return None;
    }
    // `env -S node`, `env NODE_OPTIONS=x node`: the first word that is
    // neither an option nor an assignment.
    words
        .find(|word| !word.starts_with('-') && !word.contains('='))
        .map(|name| stem(Path::new(name)))
}

/// The file name of `path` without its extension, in lower case.
fn stem(path: &Path) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// What `setup mcp --claude-desktop` needs to know of this machine.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Desktop {
    /// Claude Desktop's configuration file.
    pub config: Option<PathBuf>,
    /// How it starts the server; `None` runs a bare `opentide`.
    pub launch: Option<Launch>,
}

impl Desktop {
    /// This process's: its environment, its program and its `argv[0]`.
    pub fn probe(env: &Env, cwd: &Path) -> Desktop {
        let os = Os::current();
        let exe = std::env::current_exe().ok();
        let argv0 = std::env::args_os().next().map(PathBuf::from);
        Desktop {
            config: config_path(os, env, home(os, env).as_deref()),
            launch: launch(
                exe.as_deref(),
                argv0.as_deref(),
                env.search_path().unwrap_or_default(),
                cwd,
            ),
        }
    }
}

/// The document setup merges in: the `opentide` server under `mcpServers`,
/// started by `launch` (a bare `opentide` without one) for workspace `root`.
pub fn template(launch: Option<&Launch>, root: &Path) -> Json {
    let (command, args) = match launch {
        Some(launch) => (
            launch.command.to_string_lossy().into_owned(),
            launch.args.clone(),
        ),
        None => (
            "opentide".to_owned(),
            vec!["mcp".to_owned(), "start".to_owned()],
        ),
    };
    let entry = |pairs: Vec<(&str, Json)>| {
        Json::Object(
            pairs
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect::<Object>(),
        )
    };
    entry(vec![(
        "mcpServers",
        entry(vec![(
            SERVER,
            entry(vec![
                ("command", Json::str(command)),
                ("args", Json::Array(args.iter().map(Json::str).collect())),
                (
                    "env",
                    entry(vec![(
                        "OPENTIDE_REPO_ROOT",
                        Json::str(root.to_string_lossy()),
                    )]),
                ),
            ]),
        )]),
    )])
}

/// Merges `template` into the configuration at `config`, or writes it there
/// when there is none, or it holds nothing but blanks. Every byte of the
/// file outside the `opentide` entry stays; in that entry, setup's fields
/// (`command`, `args`, `env.OPENTIDE_REPO_ROOT`) replace the file's, and
/// every other field the user gave it (another variable of `env`) stays.
///
/// # Errors
///
/// The existing file cannot be read or merged (not UTF-8, not JSON, not an
/// object, an `mcpServers` that is not one), or it is a link to nothing,
/// which writing would replace with a file: the reason, for the warning.
/// The file is left as it is.
pub fn write(stage: &mut Stage, config: &Path, template: &Json) -> Result<(), String> {
    stage.mark_outside(config);
    if config.is_symlink() && !config.exists() {
        let target = std::fs::read_link(config)
            .map(|target| target.to_string_lossy().into_owned())
            .unwrap_or_default();
        return Err(format!("is a link to {target}, which does not exist"));
    }
    let existing = if stage.is_file(config) {
        match stage.read(config) {
            Ok(Some(bytes)) => String::from_utf8(bytes)
                .map_err(|_| "is not valid JSON (the file is not UTF-8)".to_owned())?,
            Ok(None) => String::new(),
            Err(error) => return Err(format!("cannot be read ({error})")),
        }
    } else {
        String::new()
    };
    let text = if existing.trim_start_matches('\u{feff}').trim().is_empty() {
        crate::json::document_text(template, true)
    } else {
        let template = keeping_users_fields(&existing, template);
        jsonc::merge(&existing, &template).map_err(|error| error.to_string())?
    };
    stage.write_outside(config, text);
    Ok(())
}

/// `template` with the fields of the file's own `opentide` entry that setup
/// does not write: its other keys, and the other variables of its `env`.
fn keeping_users_fields(existing: &str, template: &Json) -> Json {
    let document = jsonc::ordered(existing);
    let Some(Json::Object(own)) = document
        .as_ref()
        .and_then(|document| document.get("mcpServers"))
        .and_then(|servers| servers.get(SERVER))
    else {
        return template.clone();
    };
    let mut template = template.clone();
    let Some(Json::Object(entry)) = template
        .get_mut("mcpServers")
        .and_then(|servers| servers.get_mut(SERVER))
    else {
        return template;
    };
    let mut merged = own.clone();
    for (key, value) in &**entry {
        match (merged.get_mut(key), value) {
            (Some(Json::Object(theirs)), Json::Object(ours)) if key == "env" => {
                for (name, value) in &**ours {
                    theirs.insert(name.clone(), value.clone());
                }
            }
            _ => {
                merged.insert(key.clone(), value.clone());
            }
        }
    }
    *entry = merged;
    template
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env::from_pairs(pairs.iter().copied())
    }

    #[test]
    fn the_configuration_is_where_each_systems_claude_desktop_reads_it() {
        let home = Path::new("/home/é😀");
        let file = |folder: &Path| folder.join("Claude").join(CONFIG_FILE);
        let xdg = env(&[("XDG_CONFIG_HOME", "/xdg"), ("APPDATA", "/appdata")]);
        assert_eq!(
            config_path(Os::MacOs, &xdg, Some(home)),
            Some(file(&home.join("Library/Application Support"))),
            "macOS reads neither XDG_CONFIG_HOME nor APPDATA"
        );
        assert_eq!(
            config_path(Os::Windows, &xdg, Some(home)),
            Some(file(Path::new("/appdata")))
        );
        assert_eq!(
            config_path(Os::Windows, &env(&[("APPDATA", "")]), Some(home)),
            Some(file(&home.join("AppData").join("Roaming")))
        );
        assert_eq!(
            config_path(Os::Other, &xdg, Some(home)),
            Some(file(Path::new("/xdg")))
        );
        for unusable in ["", "relative/xdg"] {
            assert_eq!(
                config_path(
                    Os::Other,
                    &env(&[("XDG_CONFIG_HOME", unusable)]),
                    Some(home)
                ),
                Some(file(&home.join(".config"))),
                "{unusable:?}"
            );
        }
        assert_eq!(config_path(Os::MacOs, &xdg, None), None);
        assert_eq!(config_path(Os::Other, &env(&[]), None), None);
        assert_eq!(
            config_path(Os::Other, &xdg, None),
            Some(file(Path::new("/xdg")))
        );
    }

    #[test]
    fn the_home_folder_is_userprofile_on_windows_and_home_elsewhere() {
        let both = env(&[("HOME", "/h"), ("USERPROFILE", "/u")]);
        assert_eq!(home(Os::Windows, &both), Some(PathBuf::from("/u")));
        assert_eq!(home(Os::MacOs, &both), Some(PathBuf::from("/h")));
        assert_eq!(home(Os::Other, &env(&[("HOME", "")])), None);
    }

    #[cfg(unix)]
    fn executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_command_is_the_opentide_that_runs_then_its_script_then_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let start = |command: PathBuf| {
            Some(Launch {
                command,
                args: vec!["mcp".into(), "start".into()],
            })
        };
        // The standalone binary.
        let binary = root.join("opentide");
        assert_eq!(launch(Some(&binary), None, "", root), start(binary.clone()));
        // The console script: Python runs, its `opentide` beside it.
        let venv = root.join("é😀 venv").join("bin");
        std::fs::create_dir_all(&venv).unwrap();
        executable(&venv.join("python3"));
        let python = venv.join("python3");
        let resolved = Path::new("/usr/bin/python3.12");
        // No script yet, nothing on PATH: the interpreter, with -m.
        assert_eq!(
            launch(Some(resolved), Some(&python), "", root),
            Some(Launch {
                command: python.clone(),
                args: ["-m", "opentide", "mcp", "start"]
                    .map(str::to_owned)
                    .to_vec(),
            })
        );
        // On PATH.
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        executable(&bin.join("opentide"));
        assert_eq!(
            launch(Some(resolved), Some(&python), &bin.to_string_lossy(), root),
            start(bin.join("opentide"))
        );
        // Beside the interpreter as started, before PATH; a link followed
        // to the system's interpreter (`exe`) does not hide it.
        executable(&venv.join("opentide"));
        assert_eq!(
            launch(Some(resolved), Some(&python), &bin.to_string_lossy(), root),
            start(venv.join("opentide"))
        );
        // A relative argv[0] is not where anything is.
        assert_eq!(
            launch(Some(resolved), Some(Path::new("python3")), "", root),
            None
        );
        // The npm bin: a script that finds `node` on PATH. Run by Node.js
        // when Node.js runs this command; passed over otherwise.
        let npm = root.join("npm").join("bin");
        std::fs::create_dir_all(&npm).unwrap();
        executable(&npm.join("opentide"));
        std::fs::write(npm.join("opentide"), "#!/usr/bin/env node\n'use strict'\n").unwrap();
        let node = Path::new("/opt/é😀/node");
        let npm_path = npm.to_string_lossy();
        assert_eq!(
            launch(Some(node), Some(node), &npm_path, root),
            Some(Launch {
                command: node.to_path_buf(),
                args: vec![
                    npm.join("opentide").to_string_lossy().into_owned(),
                    "mcp".into(),
                    "start".into()
                ],
            })
        );
        assert_eq!(launch(Some(resolved), None, &npm_path, root), None);
        assert_eq!(
            env_interpreter(&npm.join("opentide")).as_deref(),
            Some("node")
        );
        std::fs::write(
            npm.join("opentide"),
            "#!/usr/bin/env -S NODE_OPTIONS=x node\n",
        )
        .unwrap();
        assert_eq!(
            env_interpreter(&npm.join("opentide")).as_deref(),
            Some("node")
        );
        assert_eq!(env_interpreter(&venv.join("python3")), None);
        // Node.js running the npm bin, with nothing found.
        assert_eq!(
            launch(
                Some(Path::new("/usr/bin/node")),
                Some(Path::new("/usr/bin/node")),
                "",
                root
            ),
            None
        );
    }

    #[test]
    fn the_entry_names_the_command_and_the_workspace() {
        let launch = Launch {
            command: PathBuf::from("/opt/é😀/opentide"),
            args: vec!["mcp".into(), "start".into()],
        };
        assert_eq!(
            template(Some(&launch), Path::new("/w/é😀")).to_compact(),
            r#"{"mcpServers":{"opentide":{"command":"/opt/é😀/opentide","args":["mcp","start"],"env":{"OPENTIDE_REPO_ROOT":"/w/é😀"}}}}"#
        );
        assert_eq!(
            template(None, Path::new("/w")).to_compact(),
            r#"{"mcpServers":{"opentide":{"command":"opentide","args":["mcp","start"],"env":{"OPENTIDE_REPO_ROOT":"/w"}}}}"#
        );
    }

    #[test]
    fn the_users_file_is_merged_and_setups_fields_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("Claude").join(CONFIG_FILE);
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            &config,
            "{\n  \"theme\": \"é😀\",\n  \"mcpServers\": {\n    \"other\": {\"command\": \"x\"},\n    \"opentide\": {\"command\": \"old\", \"args\": [\"mcp\", \"start\"], \"env\": {\"OPENTIDE_REPO_ROOT\": \"/old\", \"HTTPS_PROXY\": \"http://é😀:8080\"}, \"disabled\": false}\n  }\n}\n",
        )
        .unwrap();
        let mut stage = Stage::new();
        write(&mut stage, &config, &template(None, Path::new("/new"))).unwrap();
        let staged = String::from_utf8(stage.read(&config).unwrap().unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&staged).unwrap();
        assert_eq!(value["theme"], "é😀");
        assert_eq!(value["mcpServers"]["other"]["command"], "x");
        assert_eq!(value["mcpServers"]["opentide"]["command"], "opentide");
        assert_eq!(
            value["mcpServers"]["opentide"]["env"],
            serde_json::json!({"OPENTIDE_REPO_ROOT": "/new", "HTTPS_PROXY": "http://é😀:8080"}),
            "setup's variable is replaced, the user's other variables stay"
        );
        assert_eq!(value["mcpServers"]["opentide"]["disabled"], false);
        // Nothing reaches the disk before the stage commits (a plan).
        assert!(std::fs::read_to_string(&config).unwrap().contains("/old"));
        stage.commit().unwrap();
        assert_eq!(std::fs::read_to_string(&config).unwrap(), staged);
    }

    #[test]
    fn an_empty_file_is_written_as_a_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(CONFIG_FILE);
        for blank in ["", " \n\t\n", "\u{feff}\n"] {
            std::fs::write(&config, blank).unwrap();
            let mut stage = Stage::new();
            write(&mut stage, &config, &template(None, Path::new("/w"))).unwrap();
            stage.commit().unwrap();
            let value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
            assert_eq!(
                value["mcpServers"]["opentide"]["env"]["OPENTIDE_REPO_ROOT"], "/w",
                "{blank:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_nothing_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(CONFIG_FILE);
        std::os::unix::fs::symlink(dir.path().join("é😀.json"), &config).unwrap();
        let mut stage = Stage::new();
        let error = write(&mut stage, &config, &template(None, Path::new("/w"))).unwrap_err();
        assert!(error.starts_with("is a link to "), "{error}");
        assert!(error.ends_with("which does not exist"), "{error}");
        stage.commit().unwrap();
        assert!(config.is_symlink() && !config.exists());
    }

    #[test]
    fn a_file_that_cannot_be_merged_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(CONFIG_FILE);
        for (text, problem) in [
            ("{not json", "is not valid JSON"),
            ("[1, 2]", "is not a JSON object"),
            (
                "{\"mcpServers\": [\"é😀\"]}",
                "has a \"mcpServers\" that is not a JSON object",
            ),
        ] {
            std::fs::write(&config, text).unwrap();
            let mut stage = Stage::new();
            let error = write(&mut stage, &config, &template(None, Path::new("/w"))).unwrap_err();
            assert!(error.starts_with(problem), "{error}");
            assert!(stage.step().is_empty(), "{text}");
        }
    }

    #[test]
    fn a_missing_file_is_created_with_its_folders() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("é😀").join("Claude").join(CONFIG_FILE);
        let mut stage = Stage::new();
        write(&mut stage, &config, &template(None, Path::new("/w"))).unwrap();
        stage.commit().unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
        assert_eq!(
            value["mcpServers"]["opentide"]["env"]["OPENTIDE_REPO_ROOT"],
            "/w"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_file_is_written_through_and_the_link_stays() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("dotfiles").join(CONFIG_FILE);
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, "{\"mcpServers\": {}}\n").unwrap();
        let config = dir.path().join(CONFIG_FILE);
        std::os::unix::fs::symlink(&real, &config).unwrap();
        let mut stage = Stage::new();
        write(&mut stage, &config, &template(None, Path::new("/w"))).unwrap();
        stage.commit().unwrap();
        assert!(config.is_symlink());
        assert!(
            std::fs::read_to_string(&real)
                .unwrap()
                .contains("OPENTIDE_REPO_ROOT")
        );
    }
}
