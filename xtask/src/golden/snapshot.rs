//! What a case changed on disk: the case's root (`ws/`, `home/`, `tmp/`) is
//! listed before and after the run, and every entry created, changed or
//! deleted is kept with its kind, permissions and bytes.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// The kind of a file system entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link (never followed).
    Symlink,
}

/// One entry of a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its kind.
    pub kind: Kind,
    /// Permission bits (`mode & 0o7777`); 0 where the host has none.
    pub mode: u32,
    /// A file's bytes, or a link's target; empty for a directory.
    pub bytes: Vec<u8>,
}

/// A listing of a directory tree: `/`-separated relative paths to entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot(pub BTreeMap<String, Entry>);

/// How an entry changed during the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    /// It did not exist before.
    Created,
    /// Its kind, permissions or bytes differ.
    Modified,
    /// It no longer exists.
    Deleted,
}

/// A change found by [`Snapshot::changes`]; `entry` is the state after the
/// run, or before it for a deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The relative path.
    pub path: String,
    /// What happened.
    pub change: ChangeKind,
    /// The entry after the run (before, when deleted).
    pub entry: Entry,
}

impl Snapshot {
    /// Lists everything under `root`, which is not itself listed.
    pub fn take(root: &Path) -> Result<Snapshot> {
        let mut map = BTreeMap::new();
        walk(root, "", &mut map)?;
        Ok(Snapshot(map))
    }

    /// The changes from `self` (before) to `after`, in path order.
    pub fn changes(&self, after: &Snapshot) -> Vec<Change> {
        let mut out = Vec::new();
        for (path, entry) in &after.0 {
            match self.0.get(path) {
                None => out.push(Change {
                    path: path.clone(),
                    change: ChangeKind::Created,
                    entry: entry.clone(),
                }),
                Some(before) if before != entry => out.push(Change {
                    path: path.clone(),
                    change: ChangeKind::Modified,
                    entry: entry.clone(),
                }),
                Some(_) => {}
            }
        }
        for (path, entry) in &self.0 {
            if !after.0.contains_key(path) {
                out.push(Change {
                    path: path.clone(),
                    change: ChangeKind::Deleted,
                    entry: entry.clone(),
                });
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    /// The text of every regular UTF-8 file.
    pub fn texts(&self) -> impl Iterator<Item = &str> {
        self.0
            .values()
            .filter(|e| e.kind == Kind::File)
            .filter_map(|e| std::str::from_utf8(&e.bytes).ok())
    }
}

fn walk(dir: &Path, prefix: &str, map: &mut BTreeMap<String, Entry>) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let meta =
            fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        let mode = permissions(&meta);
        if meta.file_type().is_symlink() {
            let target =
                fs::read_link(&path).with_context(|| format!("read link {}", path.display()))?;
            map.insert(
                rel,
                Entry {
                    kind: Kind::Symlink,
                    mode: 0,
                    bytes: target.to_string_lossy().into_owned().into_bytes(),
                },
            );
        } else if meta.is_dir() {
            map.insert(
                rel.clone(),
                Entry {
                    kind: Kind::Dir,
                    mode,
                    bytes: Vec::new(),
                },
            );
            walk(&path, &rel, map)?;
        } else {
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            map.insert(
                rel,
                Entry {
                    kind: Kind::File,
                    mode,
                    bytes,
                },
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn permissions(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn permissions(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn finds_created_modified_and_deleted_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("ws")).unwrap();
        fs::write(root.join("ws/keep"), "same").unwrap();
        fs::write(root.join("ws/edit"), "old").unwrap();
        fs::write(root.join("ws/chmod"), "x").unwrap();
        fs::write(root.join("ws/gone"), "bye").unwrap();
        let before = Snapshot::take(root).unwrap();

        fs::write(root.join("ws/edit"), "new").unwrap();
        fs::set_permissions(root.join("ws/chmod"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_file(root.join("ws/gone")).unwrap();
        fs::create_dir(root.join("ws/sub")).unwrap();
        fs::write(root.join("ws/sub/new"), "hi").unwrap();
        std::os::unix::fs::symlink("sub", root.join("ws/link")).unwrap();
        let after = Snapshot::take(root).unwrap();

        let changes: Vec<(String, ChangeKind, Kind)> = before
            .changes(&after)
            .into_iter()
            .map(|c| (c.path, c.change, c.entry.kind))
            .collect();
        assert_eq!(
            changes,
            [
                ("ws/chmod".to_owned(), ChangeKind::Modified, Kind::File),
                ("ws/edit".to_owned(), ChangeKind::Modified, Kind::File),
                ("ws/gone".to_owned(), ChangeKind::Deleted, Kind::File),
                ("ws/link".to_owned(), ChangeKind::Created, Kind::Symlink),
                ("ws/sub".to_owned(), ChangeKind::Created, Kind::Dir),
                ("ws/sub/new".to_owned(), ChangeKind::Created, Kind::File),
            ]
        );
        let link = &after.0["ws/link"];
        assert_eq!(link.bytes, b"sub");
        assert_eq!(after.0["ws/chmod"].mode, 0o755);
        assert_eq!(after.texts().count(), 4);
    }
}
