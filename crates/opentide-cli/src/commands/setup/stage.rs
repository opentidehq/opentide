//! The files a setup step writes, held in memory before they reach the disk.
//!
//! Every setup step reads and writes through a [`Stage`]: a read sees what
//! an earlier step wrote, then the disk. A run commits each step's writes as
//! the step ends; `--plan` never commits, and lists each step's writes
//! instead (`create` for a file that did not exist before the step, `merge`
//! for one it rewrote, `delete` for one it removed). So the plan is the run,
//! minus the writing: it cannot drift from what setup does, and it needs no
//! copy of the repository (the oracle's `plan.py` copied the work tree into a
//! temporary folder and compared modification times).

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;

/// A file a step wrote, or removed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Staged {
    /// The file's bytes, and whether it is executable.
    File { bytes: Vec<u8>, executable: bool },
    /// Removed.
    Removed,
}

/// One file of a step's plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The file.
    pub path: PathBuf,
    /// `create`, `merge` or `delete`.
    pub action: &'static str,
}

/// The overlay of staged files over the disk.
#[derive(Debug, Default)]
pub struct Stage {
    /// Every staged file, by absolute path, in the order first written.
    files: IndexMap<PathBuf, Staged>,
    /// Folders a step made (`mkdir -p`), created on commit even when empty.
    dirs: BTreeSet<PathBuf>,
    /// The files written since the last [`Stage::step`], in order, each once.
    pending: IndexMap<PathBuf, ()>,
    /// What existed before the current step: staged files, by path.
    before: IndexMap<PathBuf, bool>,
    /// Links to remove before anything is written, so nothing is written
    /// through them ([`Stage::unlink`]).
    links: Vec<PathBuf>,
    /// Folders to remove once the files are written, when empty then.
    rmdirs: BTreeSet<PathBuf>,
}

impl Stage {
    /// An empty stage.
    pub fn new() -> Stage {
        Stage::default()
    }

    /// Whether `path` is a file: staged, or on disk and not removed.
    pub fn is_file(&self, path: &Path) -> bool {
        match self.files.get(path) {
            Some(Staged::File { .. }) => true,
            Some(Staged::Removed) => false,
            None => path.is_file(),
        }
    }

    /// Whether `path` is a folder: on disk, made by a step, or holding a
    /// staged file.
    pub fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
            || self.dirs.contains(path)
            || self.files.iter().any(|(file, staged)| {
                matches!(staged, Staged::File { .. }) && file.starts_with(path) && file != path
            })
    }

    /// Whether `path` exists as a file or a folder.
    pub fn exists(&self, path: &Path) -> bool {
        self.is_file(path) || self.is_dir(path) || (path.exists() && !self.files.contains_key(path))
    }

    /// The bytes of the file at `path`; `Ok(None)` when there is none.
    ///
    /// # Errors
    ///
    /// The file on disk cannot be read.
    pub fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        match self.files.get(path) {
            Some(Staged::File { bytes, .. }) => Ok(Some(bytes.clone())),
            Some(Staged::Removed) => Ok(None),
            None if path.is_file() => std::fs::read(path).map(Some),
            None => Ok(None),
        }
    }

    /// Whether the file at `path` is executable.
    pub fn is_executable(&self, path: &Path) -> bool {
        match self.files.get(path) {
            Some(Staged::File { executable, .. }) => *executable,
            Some(Staged::Removed) => false,
            None => executable_on_disk(path),
        }
    }

    /// The names of the entries of folder `dir`, staged ones included,
    /// sorted.
    pub fn entries(&self, dir: &Path) -> Vec<String> {
        let mut names: BTreeSet<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        for (file, staged) in &self.files {
            let Ok(rest) = file.strip_prefix(dir) else {
                continue;
            };
            let Some(first) = rest.components().next() else {
                continue;
            };
            let name = first.as_os_str().to_string_lossy().into_owned();
            match staged {
                Staged::File { .. } => {
                    names.insert(name);
                }
                Staged::Removed if rest.components().count() == 1 => {
                    names.remove(&name);
                }
                Staged::Removed => {}
            }
        }
        for made in &self.dirs {
            if made.parent() == Some(dir)
                && let Some(name) = made.file_name()
            {
                names.insert(name.to_string_lossy().into_owned());
            }
        }
        names.into_iter().collect()
    }

    /// Makes folder `path` and its parents.
    pub fn mkdir(&mut self, path: &Path) {
        if !path.is_dir() {
            self.dirs.insert(path.to_path_buf());
        }
    }

    fn note(&mut self, path: &Path) {
        if !self.before.contains_key(path) {
            let existed = self.is_file(path);
            self.before.insert(path.to_path_buf(), existed);
        }
        self.pending.insert(path.to_path_buf(), ());
    }

    /// Writes `bytes` to `path`, keeping whether it is executable.
    pub fn write(&mut self, path: &Path, bytes: impl Into<Vec<u8>>) {
        let executable = self.is_executable(path);
        self.write_mode(path, bytes, executable);
    }

    /// Writes `bytes` to `path`, executable or not.
    pub fn write_mode(&mut self, path: &Path, bytes: impl Into<Vec<u8>>, executable: bool) {
        self.note(path);
        self.files.insert(
            path.to_path_buf(),
            Staged::File {
                bytes: bytes.into(),
                executable,
            },
        );
    }

    /// Makes the file at `path` executable.
    ///
    /// # Errors
    ///
    /// The file on disk cannot be read.
    pub fn make_executable(&mut self, path: &Path) -> io::Result<()> {
        if let Some(bytes) = self.read(path)? {
            self.write_mode(path, bytes, true);
        }
        Ok(())
    }

    /// Removes the file at `path`.
    pub fn remove(&mut self, path: &Path) {
        if self.is_file(path) {
            self.note(path);
            self.files.insert(path.to_path_buf(), Staged::Removed);
        }
    }

    /// Removes the link at `path` (to a file or a folder), not what it
    /// points to; a later write to `path` writes a file of its own there.
    /// Nothing when `path` is not a link.
    pub fn unlink(&mut self, path: &Path) {
        if !path.is_symlink() || self.links.iter().any(|link| link == path) {
            return;
        }
        self.note(path);
        self.links.push(path.to_path_buf());
        self.files.insert(path.to_path_buf(), Staged::Removed);
    }

    /// Removes folder `path` on commit, once the files staged in or out of
    /// it are written: what a step that replaces a tree leaves of the old
    /// one. A folder that still holds a file then stays.
    pub fn remove_dir(&mut self, path: &Path) {
        if path.is_dir() && !path.is_symlink() {
            self.rmdirs.insert(path.to_path_buf());
        }
    }

    /// Whether `path` is a link the stage removes on commit.
    pub fn unlinked(&self, path: &Path) -> bool {
        self.links.iter().any(|link| link == path)
    }

    /// The files written or removed since the last call, sorted by path as
    /// the plan lists them, and the start of the next step.
    pub fn step(&mut self) -> Vec<Change> {
        let mut changes: Vec<Change> = self
            .pending
            .keys()
            .map(|path| {
                let existed = self.before.get(path).copied().unwrap_or(false);
                let action = match self.files.get(path) {
                    Some(Staged::Removed) => "delete",
                    _ if existed => "merge",
                    _ => "create",
                };
                Change {
                    path: path.clone(),
                    action,
                }
            })
            // A file a step made and then removed is no change.
            .filter(|change| {
                change.action != "delete" || self.before.get(&change.path).copied().unwrap_or(false)
            })
            .collect();
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        self.pending.clear();
        self.before.clear();
        changes
    }

    /// Writes everything staged to the disk, and empties the stage.
    ///
    /// # Errors
    ///
    /// A folder or a file cannot be written: the path and the error.
    pub fn commit(&mut self) -> Result<(), String> {
        for link in std::mem::take(&mut self.links) {
            remove_link(&link).map_err(|error| format!("{}: {error}", link.display()))?;
        }
        for dir in std::mem::take(&mut self.dirs) {
            std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        }
        for (path, staged) in std::mem::take(&mut self.files) {
            match staged {
                Staged::File { bytes, executable } => {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|error| format!("{}: {error}", parent.display()))?;
                    }
                    std::fs::write(&path, bytes)
                        .map_err(|error| format!("{}: {error}", path.display()))?;
                    if executable {
                        set_executable(&path)
                            .map_err(|error| format!("{}: {error}", path.display()))?;
                    }
                }
                Staged::Removed => match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(format!("{}: {error}", path.display())),
                },
            }
        }
        // Deepest first: a folder's subfolders go before it.
        for dir in std::mem::take(&mut self.rmdirs).into_iter().rev() {
            match std::fs::remove_dir(&dir) {
                Ok(()) => {}
                Err(_) if std::fs::read_dir(&dir).is_ok_and(|mut e| e.next().is_some()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("{}: {error}", dir.display())),
            }
        }
        self.pending.clear();
        self.before.clear();
        Ok(())
    }
}

/// Removes the link at `path` itself; nothing when it is gone already.
fn remove_link(path: &Path) -> io::Result<()> {
    if !path.is_symlink() {
        return Ok(());
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        // A link to a folder on Windows is a directory entry.
        Err(_) if cfg!(windows) => std::fs::remove_dir(path),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn executable_on_disk(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable_on_disk(path: &Path) -> bool {
    path.is_file()
}

#[cfg(unix)]
fn set_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    std::fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_see_staged_writes_and_the_disk_is_untouched_until_commit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("old.txt"), "old\n").unwrap();
        let mut stage = Stage::new();
        stage.write(&root.join("a/new.txt"), "new\n");
        stage.write(&root.join("old.txt"), "changed\n");
        assert_eq!(
            stage.read(&root.join("a/new.txt")).unwrap().as_deref(),
            Some(b"new\n".as_slice())
        );
        assert!(stage.is_dir(&root.join("a")));
        assert!(!root.join("a").exists());
        assert_eq!(stage.entries(root), ["a", "old.txt"]);
        let changes = stage.step();
        assert_eq!(
            changes
                .iter()
                .map(|change| (
                    change.path.strip_prefix(root).unwrap().to_str().unwrap(),
                    change.action
                ))
                .collect::<Vec<_>>(),
            [("a/new.txt", "create"), ("old.txt", "merge")]
        );
        // The next step sees the first step's file as existing.
        stage.write(&root.join("a/new.txt"), "again\n");
        assert_eq!(stage.step()[0].action, "merge");
        assert_eq!(
            std::fs::read_to_string(root.join("old.txt")).unwrap(),
            "old\n"
        );
        stage.commit().unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("old.txt")).unwrap(),
            "changed\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("a/new.txt")).unwrap(),
            "again\n"
        );
    }

    #[test]
    fn a_removed_file_is_a_delete_and_an_empty_folder_is_made_on_commit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("gone.txt"), "x").unwrap();
        let mut stage = Stage::new();
        stage.remove(&root.join("gone.txt"));
        stage.mkdir(&root.join("empty/folder"));
        assert!(!stage.is_file(&root.join("gone.txt")));
        assert_eq!(stage.step()[0].action, "delete");
        stage.commit().unwrap();
        assert!(!root.join("gone.txt").exists());
        assert!(root.join("empty/folder").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn an_executable_write_is_executable_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook");
        let mut stage = Stage::new();
        stage.write_mode(&path, "#!/bin/sh\n", true);
        assert!(stage.is_executable(&path));
        stage.commit().unwrap();
        assert!(executable_on_disk(&path));
    }

    #[cfg(unix)]
    #[test]
    fn rewriting_an_executable_file_keeps_it_executable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let (tool, plain) = (dir.path().join("tool"), dir.path().join("plain"));
        for (path, mode) in [(&tool, 0o755), (&plain, 0o644)] {
            std::fs::write(path, "old\n").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let mut stage = Stage::new();
        stage.write(&tool, "new\n");
        stage.write(&plain, "new\n");
        assert!(stage.is_executable(&tool));
        assert!(!stage.is_executable(&plain));
        stage.commit().unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode(&tool) & 0o111, 0o111);
        assert_eq!(mode(&plain) & 0o111, 0);
        assert_eq!(std::fs::read_to_string(&tool).unwrap(), "new\n");
    }
}
