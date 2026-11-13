//! The configuration, resolved once per run (`core/files.py`
//! `resolve_configurations`, `registry/paths.py`).
//!
//! The host's part of UC-1.5: it reads the configuration folders through the
//! [`FileSystem`], hands them to `opentide_schema::configuration::resolve`,
//! checks `paths.toml` against its model, and works out the object folders.
//! The result is immutable and shared ([`std::sync::Arc`]) by everything that
//! reads the workspace.

use std::path::{Path, PathBuf};

use opentide_schema::FromNode;
use opentide_schema::configuration::models::PathsConfiguration;
use opentide_schema::configuration::resolve::{Folder, Instance, ResolveError, Resolved, resolve};
use opentide_schema::from_node::Context;
use opentide_schema::node::{Node, Value};

use crate::fs::{EntryKind, FileSystem};
use crate::root::{OPENTIDE_DIR, Roots};

/// Families the registry never scans (`RegistryBuilder.SKIPS`).
pub const SKIPPED_FAMILIES: [&str; 2] = ["ram", "mdrv2"];

/// The configuration file the layering never reads (`_SKIPPED_CONFIG_FILES`).
const SHARING_FILE: &str = "sharing.toml";

/// The families a `[paths.objects]` folder can name.
const FOLDER_FAMILIES: [&str; 3] = ["threat", "objective", "rule"];

/// Why a workspace's configuration cannot be used; every command stops on it.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ConfigError {
    /// The layering stopped (a TOML error, a retired file, a retired proxy
    /// setting).
    #[error("{}", resolve_message(.0))]
    Resolve(ResolveError),
    /// A configuration file is not UTF-8 text, or cannot be read.
    #[error("{path}: {message}")]
    Unreadable {
        /// The file.
        path: String,
        /// Why.
        message: String,
    },
    /// The merged `paths.toml` does not fit its model.
    #[error("paths.toml: {}", .0.join("; "))]
    Paths(Vec<String>),
}

fn resolve_message(error: &ResolveError) -> String {
    match error {
        ResolveError::Parse { path, message, .. } => format!("{path}: {message}"),
        ResolveError::Retired { message, .. } | ResolveError::Proxy(message) => message.clone(),
    }
}

impl ConfigError {
    /// The diagnostic code, where the oracle gives one.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Resolve(error) => error.code(),
            Self::Unreadable { .. } => Some(opentide_schema::configuration::codes::CONFIG_PARSE),
            // The oracle raises a plain `ValueError` (`ConfigurationError`).
            Self::Paths(_) => None,
        }
    }
}

/// One family's object folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectFolder {
    /// The family (`rule`).
    pub family: String,
    /// The folder, resolved; `None` when `paths.toml` names none.
    pub path: Option<PathBuf>,
}

/// A workspace's resolved configuration.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// The merged files.
    pub resolved: Resolved,
    /// `paths.toml`, checked.
    pub paths: PathsConfiguration,
    /// The families of `[metaschemas]`, in the file's order.
    pub families: Vec<String>,
    /// The folder of each family the registry scans, in that order.
    pub object_folders: Vec<ObjectFolder>,
    /// The configuration folders this configuration reads or would read:
    /// a change inside one of them resolves the configuration again.
    pub folders: Vec<PathBuf>,
    /// Configuration files read.
    pub files_read: usize,
}

impl Configuration {
    /// The object folder of `family`, if it has one.
    pub fn folder(&self, family: &str) -> Option<&Path> {
        self.object_folders
            .iter()
            .find(|folder| folder.family == family)
            .and_then(|folder| folder.path.as_deref())
    }
}

/// Reads a configuration folder: each file directly in it or in a folder
/// directly under it, and the names of those folders. `None` when it is not a
/// folder.
fn read_folder(
    fs: &dyn FileSystem,
    dir: &Path,
    files_read: &mut usize,
) -> Result<Option<Folder>, ConfigError> {
    if !fs.is_dir(dir) {
        return Ok(None);
    }
    let shown = dir.to_string_lossy().into_owned();
    let unreadable = |path: &Path, message: String| ConfigError::Unreadable {
        path: path.to_string_lossy().into_owned(),
        message,
    };
    let mut folder = Folder {
        path: shown,
        ..Folder::default()
    };
    let mut read = |path: &Path| -> Result<String, ConfigError> {
        *files_read += 1;
        let bytes = fs
            .read(path)
            .map_err(|error| unreadable(path, error.to_string()))?;
        String::from_utf8(bytes).map_err(|error| {
            unreadable(
                path,
                format!(
                    "the file is not UTF-8 text (offset {}); save it as UTF-8",
                    error.utf8_error().valid_up_to()
                ),
            )
        })
    };
    let mut entries = fs
        .read_dir(dir)
        .map_err(|error| unreadable(dir, error.to_string()))?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    for entry in entries {
        let path = dir.join(&entry.file_name);
        match entry.kind {
            EntryKind::Dir => {
                folder.folders.push(entry.name.clone());
                // A hidden or private folder is never merged: nothing in it is read.
                if entry.name.starts_with('.') || entry.name.starts_with("__") {
                    continue;
                }
                let mut nested = fs
                    .read_dir(&path)
                    .map_err(|error| unreadable(&path, error.to_string()))?;
                nested.sort_by(|a, b| a.name.cmp(&b.name));
                for file in nested {
                    // Only TOML files are ever parsed; nothing else is read.
                    if file.kind == EntryKind::File && is_toml(&file.name) {
                        let text = read(&path.join(&file.file_name))?;
                        folder
                            .files
                            .push((format!("{}/{}", entry.name, file.name), text));
                    }
                }
            }
            EntryKind::File => {
                // Every top-level file name counts (a retired `global.toml`),
                // but only TOML files are read, and never `sharing.toml`:
                // sharing has a loader of its own (`_SKIPPED_CONFIG_FILES`),
                // so a sharing.toml that is not UTF-8 is `sharing-config`'s
                // finding, not a configuration every command stops on.
                let text = if is_toml(&entry.name) && entry.name != SHARING_FILE {
                    read(&path)?
                } else {
                    String::new()
                };
                folder.files.push((entry.name, text));
            }
            EntryKind::Other => {}
        }
    }
    Ok(Some(folder))
}

/// Whether `name` is a TOML file's: case-sensitive, as the oracle's
/// `glob("*.toml")` and `endswith(".toml")` are on Linux.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "the oracle matches `.toml` case-sensitively"
)]
fn is_toml(name: &str) -> bool {
    name.ends_with(".toml")
}

fn string_at<'n>(node: &'n Node, path: &[&str]) -> Option<&'n str> {
    let mut current = node;
    for key in path {
        current = current.get(key)?;
    }
    current.value.as_str()
}

/// The configuration folders read and merged, before `paths.toml` is checked.
struct Merged {
    resolved: Resolved,
    folders: Vec<PathBuf>,
    files_read: usize,
}

/// Reads the configuration folders of the workspace at `roots` and merges
/// them.
fn read(fs: &dyn FileSystem, roots: &Roots) -> Result<Merged, ConfigError> {
    let mut files_read = 0;
    let own_dir = roots.workspace.join(OPENTIDE_DIR).join("configurations");
    let overlay_dir = roots
        .repo
        .join("tests")
        .join("fixtures")
        .join("generation")
        .join("configurations");
    let parent_dir = roots
        .workspace
        .parent()
        .map(|parent| parent.join(OPENTIDE_DIR).join("configurations"));
    let own = read_folder(fs, &own_dir, &mut files_read)?;
    let overlay = if roots.tide_workspace {
        read_folder(fs, &overlay_dir, &mut files_read)?
    } else {
        None
    };
    // `parent_dir` is never `own_dir`: a folder's parent is not the folder.
    let parent = match &parent_dir {
        Some(dir) if !roots.tide_workspace => read_folder(fs, dir, &mut files_read)?,
        _ => None,
    };
    let resolved = resolve(&Instance {
        workspace: own.as_ref(),
        overlay: overlay.as_ref(),
        parent: parent.as_ref(),
        skip_parent: roots.tide_workspace,
    })
    .map_err(ConfigError::Resolve)?;
    let mut folders = vec![own_dir];
    if roots.tide_workspace {
        folders.push(overlay_dir);
    } else if let Some(dir) = parent_dir {
        folders.push(dir);
    }
    Ok(Merged {
        resolved,
        folders,
        files_read,
    })
}

/// Resolves the configuration of the workspace at `roots` and checks
/// nothing: the merged files as `core/files.py` `resolve_configurations`
/// returns them, for what reads a configuration whose `paths.toml` its model
/// refuses (`setup ci`'s statuses, #957). [`load`] checks it.
///
/// # Errors
///
/// A [`ConfigError`] other than [`ConfigError::Paths`]: the layering
/// stopped, or a configuration file cannot be read.
pub fn resolve_only(fs: &dyn FileSystem, roots: &Roots) -> Result<Resolved, ConfigError> {
    read(fs, roots).map(|merged| merged.resolved)
}

/// Resolves the configuration of the workspace at `roots` and checks
/// `paths.toml` against its model.
///
/// # Errors
///
/// A [`ConfigError`]: every command stops on it.
pub fn load(fs: &dyn FileSystem, roots: &Roots) -> Result<Configuration, ConfigError> {
    let Merged {
        resolved,
        folders,
        files_read,
    } = read(fs, roots)?;

    let paths_node = resolved.get("paths");
    let paths = match paths_node {
        Some(node) => {
            let mut cx = Context::new();
            let model = PathsConfiguration::from_node(node, &mut cx);
            let errors = cx.into_errors();
            match model {
                Some(model) if errors.is_empty() => model,
                _ => {
                    return Err(ConfigError::Paths(
                        errors
                            .iter()
                            .map(|error| {
                                format!("{}: {}", error.field_path().join("."), error.message)
                            })
                            .collect(),
                    ));
                }
            }
        }
        None => {
            return Err(ConfigError::Paths(vec![
                "the bundled paths.toml is missing".to_owned(),
            ]));
        }
    };
    let paths_node = paths_node
        .cloned()
        .unwrap_or_else(|| Node::null_at(opentide_schema::node::Mark::default()));

    let families: Vec<String> = match paths_node.get("metaschemas").map(|node| &node.value) {
        Some(Value::Map(entries)) => entries
            .iter()
            .map(|entry| entry.key.value.to_string())
            .collect(),
        _ => Vec::new(),
    };
    let object_folders = families
        .iter()
        .filter(|family| !SKIPPED_FAMILIES.contains(&family.as_str()))
        .map(|family| ObjectFolder {
            family: family.clone(),
            path: FOLDER_FAMILIES
                .contains(&family.as_str())
                .then(|| string_at(&paths_node, &["paths", "objects", family]))
                .flatten()
                .filter(|relative| !relative.is_empty())
                .map(|relative| fs.resolve(&roots.workspace.join(relative))),
        })
        .collect();
    Ok(Configuration {
        resolved,
        paths,
        families,
        object_folders,
        folders,
        files_read,
    })
}
