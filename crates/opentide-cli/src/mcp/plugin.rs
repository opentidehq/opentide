//! Which detection workspace the server serves when an Agent Plugin starts it
//! (#431, `src/opentide/mcp_server/workspace.py`).
//!
//! An Agent Plugins 1.0 client starts a plugin's stdio server in the plugin
//! root. For the opentide skills plugin that root is the skills package, not
//! the user's catalogue. When the server starts in a plugin root that is not
//! itself a workspace, it takes the host's project directory instead, and
//! otherwise refuses the catalogue tools with an error that says how to name
//! the workspace.

use std::path::{Path, PathBuf};

use opentide_workspace::root::{find_workspace_root, is_workspace_root};
use opentide_workspace::{FileSystem, OsFs};

use crate::env::Env;

/// The `$schema` prefix of an Agent Plugins manifest (`plugin.json`).
pub const AGENT_PLUGINS_SCHEMA: &str = "https://agent-plugins.org/schemas/";

/// The variables that name the workspace explicitly.
pub const WORKSPACE_VARIABLES: [&str; 2] = ["OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"];

/// The project directories hosts give the servers they start, most specific
/// first. `PWD` is the directory the host itself was started in.
pub const HOST_PROJECT_VARIABLES: [&str; 2] = ["CLAUDE_PROJECT_DIR", "PWD"];

/// The code of a launch that found no workspace.
pub const WORKSPACE_NOT_FOUND: &str = "workspace_not_found";

/// How the server found its workspace after starting in a plugin root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginLaunch {
    /// The plugin root it started in.
    pub plugin_root: PathBuf,
    /// The workspace a host variable named, if one did.
    pub workspace: Option<PathBuf>,
}

impl PluginLaunch {
    /// Why there is no workspace to serve, when there is none.
    pub fn problem(&self) -> Option<String> {
        self.workspace.is_none().then(|| {
            format!(
                "{WORKSPACE_NOT_FOUND}: opentide was started in the Agent Plugin at {}, which is \
                 not a detection workspace, and the host named no project that is one. Set \
                 OPENTIDE_REPO_ROOT to your detection repository in the host's MCP server \
                 settings, or add the server to the project with 'opentide setup mcp'.",
                self.plugin_root.display()
            )
        })
    }
}

/// Whether `path` holds an Agent Plugins manifest (`plugin.json` with its `$schema`).
pub fn is_agent_plugin_root(fs: &dyn FileSystem, path: &Path) -> bool {
    let Ok(bytes) = fs.read(&path.join("plugin.json")) else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|manifest| {
            manifest
                .get("$schema")
                .and_then(serde_json::Value::as_str)
                .map(|schema| schema.starts_with(AGENT_PLUGINS_SCHEMA))
        })
        .unwrap_or(false)
}

/// `None` unless the server starts in `cwd`, an Agent Plugin root that is no
/// workspace (`resolve_plugin_launch`). A workspace a variable names wins,
/// and a plugin that is also a detection workspace is served as one.
pub fn resolve(fs: &dyn FileSystem, cwd: &Path, env: &Env) -> Option<PluginLaunch> {
    let set = |name: &str| env.get(name).filter(|value| !value.is_empty());
    if WORKSPACE_VARIABLES
        .iter()
        .filter_map(|name| set(name))
        .any(|value| is_workspace_root(fs, Path::new(value)))
    {
        return None;
    }
    let start = fs.resolve(cwd);
    if !is_agent_plugin_root(fs, &start) || is_workspace_root(fs, &find_workspace_root(fs, &start))
    {
        return None;
    }
    for name in HOST_PROJECT_VARIABLES {
        let Some(value) = set(name) else { continue };
        let candidate = find_workspace_root(fs, Path::new(value));
        if candidate != start && is_workspace_root(fs, &candidate) {
            return Some(PluginLaunch {
                plugin_root: start,
                workspace: Some(candidate),
            });
        }
    }
    Some(PluginLaunch {
        plugin_root: start,
        workspace: None,
    })
}

/// The server's environment once `launch` applies: the workspace variables
/// set to the workspace a host named; and why there is none, if so.
pub fn apply(env: Env, launch: Option<&PluginLaunch>) -> (Env, Option<String>) {
    let Some(launch) = launch else {
        return (env, None);
    };
    match &launch.workspace {
        None => (env, launch.problem()),
        Some(workspace) => {
            let shown = workspace.to_string_lossy().into_owned();
            let pairs: Vec<(String, String)> = env
                .iter()
                .filter(|(name, _)| !WORKSPACE_VARIABLES.contains(name))
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .chain(
                    WORKSPACE_VARIABLES
                        .iter()
                        .map(|name| ((*name).to_owned(), shown.clone())),
                )
                .collect();
            (Env::from_pairs(pairs), None)
        }
    }
}

/// [`resolve`] and [`apply`] on the disk.
pub fn served(env: Env, cwd: &Path) -> (Env, Option<String>) {
    let launch = resolve(&OsFs, cwd, &env);
    apply(env, launch.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(dir: &Path) {
        std::fs::write(
            dir.join("plugin.json"),
            r#"{"$schema": "https://agent-plugins.org/schemas/plugin.json"}"#,
        )
        .unwrap();
    }

    #[test]
    fn a_plugin_root_without_a_named_workspace_is_a_problem() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("plugin");
        std::fs::create_dir_all(&root).unwrap();
        plugin(&root);
        let launch = resolve(&OsFs, &root, &Env::from_pairs::<&str, &str>([])).unwrap();
        assert_eq!(launch.workspace, None);
        let (_, problem) = apply(Env::default(), Some(&launch));
        assert!(
            problem
                .unwrap()
                .starts_with("workspace_not_found: opentide was started"),
            "the refusal names its code"
        );
    }

    #[test]
    fn the_host_project_is_served_from_a_plugin_root() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("plugin");
        let project = scratch.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(project.join(".opentide")).unwrap();
        plugin(&root);
        let env = Env::from_pairs([("CLAUDE_PROJECT_DIR", project.to_string_lossy())]);
        let launch = resolve(&OsFs, &root, &env).unwrap();
        assert_eq!(launch.workspace, Some(OsFs.resolve(&project)));
        let (env, problem) = apply(env, Some(&launch));
        assert_eq!(problem, None);
        assert_eq!(
            env.get("OPENTIDE_REPO_ROOT"),
            Some(OsFs.resolve(&project).to_string_lossy().as_ref())
        );
    }

    #[test]
    fn a_named_workspace_or_a_plain_folder_is_no_plugin_launch() {
        let scratch = tempfile::tempdir().unwrap();
        let workspace = scratch.path().join("ws");
        std::fs::create_dir_all(workspace.join(".opentide")).unwrap();
        plugin(scratch.path());
        let env = Env::from_pairs([("OPENTIDE_REPO_ROOT", workspace.to_string_lossy())]);
        assert_eq!(resolve(&OsFs, scratch.path(), &env), None);
        let plain = scratch.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        assert_eq!(resolve(&OsFs, &plain, &Env::default()), None);
        assert!(!is_agent_plugin_root(&OsFs, &plain));
        assert_eq!(apply(Env::default(), None).1, None);
    }
}
