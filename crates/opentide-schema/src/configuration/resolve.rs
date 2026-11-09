//! The layering of the configuration files (`core/files.py`
//! `resolve_configurations`): the bundled defaults, then the workspace's
//! `.opentide/configurations/`, then the parent instance's; each layer merged
//! onto the ones before ([`super::merge::deep_merge`]).
//!
//! A folder's files are read as the oracle reads them: each `.toml` file at
//! the top (but `sharing.toml`, which merges block by block,
//! [`super::sharing`]) under its name without `.toml`, and each folder at the
//! top that is not hidden (`.x`) or private (`__x`) as a table of its
//! `.toml` files by stem. `platforms` is also `systems`, the name 0.x used.
//!
//! Resolution happens once per run: every file is parsed once
//! ([`Resolved::parsed`] counts them), and every consumer reads the
//! [`Resolved`] tree.

use std::sync::Arc;

use super::merge::{deep_merge, empty};
use super::{bundled, checks, toml};
use crate::node::{Entry, Mark, Node, Value};

/// A configuration folder, as the host read it: every file directly in it or
/// in a folder directly under it, by its path relative to the folder
/// (`deployment.toml`, `platforms/splunk.toml`), and every folder directly
/// under it (`platforms`), so that an empty one counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Folder {
    /// Where the folder is, for messages (`<workspace>/.opentide/configurations`).
    pub path: String,
    /// `(relative path, text)`.
    pub files: Vec<(String, String)>,
    /// The folders directly under it, by name.
    pub folders: Vec<String>,
}

impl Folder {
    /// The bundled folder.
    pub fn bundled() -> Self {
        let mut folders: Vec<String> = Vec::new();
        for (path, _) in bundled::FILES {
            if let Some((folder, _)) = path.split_once('/')
                && !folders.iter().any(|seen| seen == folder)
            {
                folders.push(folder.to_owned());
            }
        }
        Self {
            path: "opentide/data/configurations".to_owned(),
            files: bundled::FILES
                .iter()
                .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
                .collect(),
            folders,
        }
    }

    fn has_file(&self, name: &str) -> bool {
        self.files.iter().any(|(path, _)| path == name)
    }

    fn has_entry(&self, name: &str) -> bool {
        self.has_file(name) || self.folders.iter().any(|folder| folder == name)
    }
}

/// The folders a workspace's configuration resolves from.
#[derive(Debug, Clone, Default)]
pub struct Instance<'a> {
    /// `<workspace>/.opentide/configurations`, when it exists.
    pub workspace: Option<&'a Folder>,
    /// The test fixture overlay the oracle merges when
    /// `OPENTIDE_TIDE_WORKSPACE` is set (it then skips the parent).
    pub overlay: Option<&'a Folder>,
    /// `<workspace>/../.opentide/configurations`, when it exists and is not
    /// the workspace's own.
    pub parent: Option<&'a Folder>,
}

/// Why a workspace's configuration does not resolve; every command stops
/// on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// A file is not TOML (`config_parse`).
    Parse {
        /// The file.
        path: String,
        /// What is wrong.
        message: String,
        /// Where, from 1.
        line: Option<usize>,
        /// Where, from 1, in code points.
        column: Option<usize>,
    },
    /// A file or folder opentide no longer reads (`retired_configuration_file`).
    Retired {
        /// The entry.
        path: String,
        /// What replaces it.
        message: String,
    },
    /// A retired proxy setting.
    Proxy(String),
}

impl ResolveError {
    /// The diagnostic code; the oracle gives a retired proxy setting none
    /// (a plain `ValueError`).
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Parse { .. } => Some(super::codes::CONFIG_PARSE),
            Self::Retired { .. } => Some(super::codes::RETIRED_CONFIGURATION_FILE),
            Self::Proxy(_) => None,
        }
    }

    /// The message.
    pub fn message(&self) -> &str {
        match self {
            Self::Parse { message, .. } | Self::Retired { message, .. } | Self::Proxy(message) => {
                message
            }
        }
    }
}

/// A resolved configuration: one table per file (`deployment`,
/// `platforms.splunk`, ...).
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The merged tree.
    pub tree: Node,
    /// How many TOML documents resolution parsed: one per file read.
    pub parsed: usize,
}

impl Resolved {
    /// The table of `key` (`deployment`, `platforms`), if any.
    pub fn get(&self, key: &str) -> Option<&Node> {
        self.tree.get(key).map(AsRef::as_ref)
    }

    /// The tree as JSON ([`super::merge::to_json`]).
    pub fn to_json(&self) -> serde_json::Value {
        super::merge::to_json(&self.tree)
    }

    /// `validate --check configuration`'s findings ([`checks::workspace_issues`]).
    pub fn issues(&self) -> Vec<super::Finding> {
        checks::workspace_issues(&self.tree)
    }
}

fn key_node(key: &str) -> Arc<Node> {
    Arc::new(Node {
        value: Value::Str(key.to_owned()),
        start: Mark::default(),
        end: Mark::default(),
    })
}

fn table(entries: Vec<(String, Node)>) -> Node {
    Node {
        value: Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| Entry {
                    key: key_node(&key),
                    value: Arc::new(value),
                })
                .collect(),
        ),
        start: Mark::default(),
        end: Mark::default(),
    }
}

/// `Path.stem`: the name less its last suffix; a dotfile keeps its name.
fn stem(name: &str) -> &str {
    match name.rfind('.') {
        Some(0) | None => name,
        Some(dot) => &name[..dot],
    }
}

fn parse(
    folder: &Folder,
    relative: &str,
    text: &str,
    parsed: &mut usize,
) -> Result<Node, ResolveError> {
    *parsed += 1;
    toml::parse(text).map_err(|error| ResolveError::Parse {
        path: format!("{}/{relative}", folder.path),
        message: error.message,
        line: error.line,
        column: error.column,
    })
}

/// A folder's documents (`_fetch_configs`).
fn fetch(folder: &Folder, parsed: &mut usize) -> Result<Node, ResolveError> {
    let mut names: Vec<&str> = folder
        .files
        .iter()
        .filter(|(path, _)| !path.contains('/'))
        .map(|(path, _)| path.as_str())
        .chain(folder.folders.iter().map(String::as_str))
        .collect();
    names.sort_unstable();
    names.dedup();
    let mut entries = Vec::new();
    for name in names {
        if let Some((_, text)) = folder.files.iter().find(|(path, _)| path == name) {
            if !checks::is_toml(name) || name == "sharing.toml" {
                continue;
            }
            let key = name.strip_suffix(".toml").unwrap_or(name);
            entries.push((key.to_owned(), parse(folder, name, text, parsed)?));
            continue;
        }
        if name.starts_with('.') || name.starts_with("__") {
            continue;
        }
        let prefix = format!("{name}/");
        let mut nested: Vec<(&str, &str)> = folder
            .files
            .iter()
            .filter_map(|(path, text)| {
                let file = path.strip_prefix(&prefix)?;
                (!file.contains('/') && checks::is_toml(file)).then_some((file, text.as_str()))
            })
            .collect();
        nested.sort_unstable_by_key(|(file, _)| *file);
        let mut tables = Vec::new();
        for (file, text) in nested {
            let document = parse(folder, &format!("{prefix}{file}"), text, parsed)?;
            tables.push((stem(file).to_owned(), document));
        }
        entries.push((name.to_owned(), table(tables)));
    }
    Ok(table(entries))
}

fn reject_retired(folder: &Folder) -> Result<(), ResolveError> {
    for (name, replacement) in checks::RETIRED_CONFIGURATIONS {
        if folder.has_entry(name) {
            return Err(ResolveError::Retired {
                path: format!("{}/{name}", folder.path),
                message: format!("{name} is not read by opentide: {replacement}."),
            });
        }
    }
    Ok(())
}

/// Merges a layer: `systems` is the same table as `platforms`.
fn merge_layer(unified: &mut Node, layer: &Node) {
    let Value::Map(entries) = &layer.value else {
        return;
    };
    for entry in entries {
        let key = match entry.key.value.as_str() {
            Some("systems") => "platforms",
            Some(key) => key,
            None => continue,
        };
        let single = table(vec![(key.to_owned(), (*entry.value).clone())]);
        deep_merge(unified, &single);
    }
}

/// Resolves the configuration of a workspace: the bundled folder, then
/// `instance`'s folders.
///
/// # Errors
///
/// A [`ResolveError`]: a file that is not TOML, a retired file or folder, a
/// retired proxy setting.
pub fn resolve(instance: &Instance<'_>) -> Result<Resolved, ResolveError> {
    let mut parsed = 0;
    let mut unified = fetch(&Folder::bundled(), &mut parsed)?;
    if unified.get("platforms").is_none() {
        merge_layer(
            &mut unified,
            &table(vec![("platforms".to_owned(), empty())]),
        );
    }
    if let Some(workspace) = instance.workspace {
        reject_retired(workspace)?;
        let layer = fetch(workspace, &mut parsed)?;
        merge_layer(&mut unified, &layer);
    }
    if let Some(overlay) = instance.overlay {
        let layer = fetch(overlay, &mut parsed)?;
        merge_layer(&mut unified, &layer);
    }
    if let (Some(parent), None) = (instance.parent, instance.overlay) {
        reject_retired(parent)?;
        let layer = fetch(parent, &mut parsed)?;
        merge_layer(&mut unified, &layer);
    }
    reject_retired_proxy(&unified)?;
    if let Some(platforms) = unified.get("platforms").map(|node| (**node).clone()) {
        let Value::Map(entries) = &mut unified.value else {
            return Ok(Resolved {
                tree: unified,
                parsed,
            });
        };
        entries.retain(|entry| entry.key.value.as_str() != Some("systems"));
        entries.push(Entry {
            key: key_node("systems"),
            value: Arc::new(platforms),
        });
    }
    Ok(Resolved {
        tree: unified,
        parsed,
    })
}

fn reject_retired_proxy(unified: &Node) -> Result<(), ResolveError> {
    let message = "Pass the proxy URL with `opentide --proxy http://[user:pass@]host:port`.";
    if let Some(deployment) = unified.get("deployment")
        && matches!(deployment.value, Value::Map(_))
        && deployment.get("proxy").is_some()
    {
        return Err(ResolveError::Proxy(format!(
            "deployment.toml [proxy] is retired. {message}"
        )));
    }
    if let Some(cve) = unified.get("documentation").and_then(|doc| doc.get("cve"))
        && matches!(cve.value, Value::Map(_))
        && cve.get("proxy").is_some()
    {
        return Err(ResolveError::Proxy(format!(
            "[cve].proxy is retired. {message}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(files: &[(&str, &str)], folders: &[&str]) -> Folder {
        Folder {
            path: "/w/.opentide/configurations".to_owned(),
            files: files
                .iter()
                .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
                .collect(),
            folders: folders.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    #[test]
    fn the_bundled_folder_resolves_with_platforms_twice() {
        let resolved = resolve(&Instance::default()).unwrap();
        let json = resolved.to_json();
        assert_eq!(json["platforms"], json["systems"]);
        assert!(json["platforms"]["splunk"].is_object());
        assert!(json.get("sharing").is_none());
        assert_eq!(resolved.parsed, bundled::FILES.len() - 1);
    }

    #[test]
    fn workspace_then_parent_win_and_each_file_is_parsed_once() {
        let workspace = folder(
            &[
                ("deployment.toml", "default_responders = \"soc\"\n"),
                ("platforms/splunk.toml", "[platform]\nenabled = true\n"),
                ("notes.txt", "x"),
            ],
            &["platforms", ".hidden", "empty"],
        );
        let parent = folder(
            &[("deployment.toml", "default_responders = \"cert\"\n")],
            &[],
        );
        let resolved = resolve(&Instance {
            workspace: Some(&workspace),
            overlay: None,
            parent: Some(&parent),
        })
        .unwrap();
        let json = resolved.to_json();
        assert_eq!(json["deployment"]["default_responders"], "cert");
        assert_eq!(json["platforms"]["splunk"]["platform"]["enabled"], true);
        assert_eq!(json["systems"]["splunk"]["platform"]["enabled"], true);
        assert_eq!(json["empty"], serde_json::json!({}));
        assert!(json.get(".hidden").is_none());
        assert_eq!(resolved.parsed, bundled::FILES.len() - 1 + 3);
    }

    #[test]
    fn retired_entries_and_proxies_stop_resolution() {
        let workspace = folder(&[("global.toml", "")], &[]);
        let error = resolve(&Instance {
            workspace: Some(&workspace),
            ..Instance::default()
        })
        .unwrap_err();
        assert_eq!(error.code(), Some("retired_configuration_file"));
        let systems = folder(&[], &["systems"]);
        assert!(matches!(
            resolve(&Instance {
                workspace: Some(&systems),
                ..Instance::default()
            }),
            Err(ResolveError::Retired { .. })
        ));
        let proxy = folder(&[("deployment.toml", "[proxy]\nurl = \"x\"\n")], &[]);
        assert!(matches!(
            resolve(&Instance {
                workspace: Some(&proxy),
                ..Instance::default()
            }),
            Err(ResolveError::Proxy(_))
        ));
        let broken = folder(&[("paths.toml", "x = = 1\n")], &[]);
        assert!(matches!(
            resolve(&Instance {
                workspace: Some(&broken),
                ..Instance::default()
            }),
            Err(ResolveError::Parse { line: Some(1), .. })
        ));
    }
}
