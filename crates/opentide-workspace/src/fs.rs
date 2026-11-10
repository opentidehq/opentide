//! The filesystem a workspace is read through.
//!
//! Loading never calls `std::fs` directly: it goes through [`FileSystem`],
//! so the language server can serve its open buffers, a test can build a
//! workspace in memory ([`MemoryFs`]), and every read is counted in one
//! place. [`OsFs`] is the disk.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, PoisonError, RwLock};

/// What a path names, after following symbolic links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// Anything else: a socket, a device, a broken link.
    Other,
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's name (lossily decoded when it is not UTF-8).
    pub name: String,
    /// What it names, links followed.
    pub kind: EntryKind,
    /// Whether the entry itself is a symbolic link. A walk does not descend
    /// into a linked directory, as Python's `Path.rglob` does not.
    pub symlink: bool,
}

/// The read side of a filesystem.
pub trait FileSystem: Send + Sync {
    /// The bytes of the file at `path`.
    ///
    /// # Errors
    ///
    /// The file cannot be read.
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// What `path` names, links followed.
    ///
    /// # Errors
    ///
    /// `NotFound` when nothing is there; any other error when it cannot be
    /// examined.
    fn kind(&self, path: &Path) -> io::Result<EntryKind>;

    /// The entries of the directory at `path`, in no particular order.
    ///
    /// # Errors
    ///
    /// The directory cannot be listed.
    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>>;

    /// `path` made absolute and its symbolic links resolved as far as the
    /// path exists, as Python's `Path.resolve()` does: a path that does not
    /// exist (yet) still resolves, lexically past its last existing parent.
    fn resolve(&self, path: &Path) -> PathBuf;

    /// Whether `path` is a directory.
    fn is_dir(&self, path: &Path) -> bool {
        matches!(self.kind(path), Ok(EntryKind::Dir))
    }

    /// Whether `path` is a regular file.
    fn is_file(&self, path: &Path) -> bool {
        matches!(self.kind(path), Ok(EntryKind::File))
    }
}

/// The disk.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsFs;

impl FileSystem for OsFs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        let metadata = std::fs::metadata(path)?;
        Ok(if metadata.is_dir() {
            EntryKind::Dir
        } else if metadata.is_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        })
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let symlink = entry.file_type()?.is_symlink();
            // A broken link, or one the process may not follow, is neither.
            let kind = self.kind(&entry.path()).unwrap_or(EntryKind::Other);
            entries.push(DirEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                kind,
                symlink,
            });
        }
        Ok(entries)
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let mut resolved = PathBuf::new();
        for component in absolute.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => resolved.push(component),
                Component::CurDir => {}
                Component::ParentDir => {
                    resolved.pop();
                }
                Component::Normal(name) => {
                    let candidate = resolved.join(name);
                    resolved = std::fs::canonicalize(&candidate)
                        .map(strip_verbatim)
                        .unwrap_or(candidate);
                }
            }
        }
        resolved
    }
}

/// `canonicalize` on Windows answers `\\?\C:\...`; the rest of the path, and
/// every path a user gives, has no such prefix.
fn strip_verbatim(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let text = path.to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\")
            && !rest.starts_with("UNC\\")
        {
            return PathBuf::from(rest.to_owned());
        }
    }
    path
}

/// `path` with `.` and `..` folded away, lexically.
pub fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

#[derive(Debug, Default)]
struct Tree {
    files: BTreeMap<PathBuf, Vec<u8>>,
    dirs: BTreeSet<PathBuf>,
}

/// A filesystem in memory, for tests and for hosts that hold their files
/// (the language server's open buffers). Paths are taken lexically: no
/// links. It counts every read, by path ([`MemoryFs::reads`]).
#[derive(Debug, Default)]
pub struct MemoryFs {
    tree: RwLock<Tree>,
    reads: Mutex<HashMap<PathBuf, usize>>,
}

impl MemoryFs {
    /// An empty filesystem.
    pub fn new() -> Self {
        Self::default()
    }

    fn tree(&self) -> std::sync::RwLockReadGuard<'_, Tree> {
        self.tree.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn tree_mut(&self) -> std::sync::RwLockWriteGuard<'_, Tree> {
        self.tree.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes `bytes` to `path`, creating its parent directories.
    pub fn write(&self, path: impl AsRef<Path>, bytes: impl Into<Vec<u8>>) {
        let path = normalise(path.as_ref());
        let mut tree = self.tree_mut();
        let mut parent = path.parent();
        while let Some(dir) = parent {
            if dir.as_os_str().is_empty() {
                break;
            }
            tree.dirs.insert(dir.to_path_buf());
            parent = dir.parent();
        }
        tree.files.insert(path, bytes.into());
    }

    /// Creates the directory `path` and its parents.
    pub fn create_dir(&self, path: impl AsRef<Path>) {
        let path = normalise(path.as_ref());
        let mut tree = self.tree_mut();
        let mut current = Some(path.as_path());
        while let Some(dir) = current {
            if dir.as_os_str().is_empty() {
                break;
            }
            tree.dirs.insert(dir.to_path_buf());
            current = dir.parent();
        }
    }

    /// Removes the file or directory tree at `path`; whether anything was
    /// there.
    pub fn remove(&self, path: impl AsRef<Path>) -> bool {
        let path = normalise(path.as_ref());
        let mut tree = self.tree_mut();
        let before = tree.files.len() + tree.dirs.len();
        tree.files.retain(|file, _| !file.starts_with(&path));
        tree.dirs.retain(|dir| !dir.starts_with(&path));
        before != tree.files.len() + tree.dirs.len()
    }

    /// Moves the file or directory tree at `from` to `to`, replacing what is
    /// there; whether anything moved.
    pub fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> bool {
        let from = normalise(from.as_ref());
        let to = normalise(to.as_ref());
        if from == to || to.starts_with(&from) {
            return false;
        }
        let moved: Vec<(PathBuf, Vec<u8>)> = {
            let tree = self.tree();
            tree.files
                .iter()
                .filter(|(path, _)| path.starts_with(&from))
                .map(|(path, bytes)| (path.clone(), bytes.clone()))
                .collect()
        };
        let dirs: Vec<PathBuf> = self
            .tree()
            .dirs
            .iter()
            .filter(|dir| dir.starts_with(&from))
            .cloned()
            .collect();
        if moved.is_empty() && dirs.is_empty() {
            return false;
        }
        self.remove(&to);
        self.remove(&from);
        for dir in dirs {
            if let Ok(rest) = dir.strip_prefix(&from) {
                self.create_dir(to.join(rest));
            }
        }
        for (path, bytes) in moved {
            if let Ok(rest) = path.strip_prefix(&from) {
                let target = if rest.as_os_str().is_empty() {
                    to.clone()
                } else {
                    to.join(rest)
                };
                self.write(target, bytes);
            }
        }
        true
    }

    /// How many times each path was read.
    pub fn reads(&self) -> HashMap<PathBuf, usize> {
        self.reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Forgets the read counts.
    pub fn reset_reads(&self) {
        self.reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("{} does not exist", path.display()),
    )
}

impl FileSystem for MemoryFs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let path = normalise(path);
        *self
            .reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(path.clone())
            .or_default() += 1;
        let tree = self.tree();
        match tree.files.get(&path) {
            Some(bytes) => Ok(bytes.clone()),
            None if tree.dirs.contains(&path) => Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                format!("{} is a directory", path.display()),
            )),
            None => Err(not_found(&path)),
        }
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        let path = normalise(path);
        let tree = self.tree();
        if tree.files.contains_key(&path) {
            Ok(EntryKind::File)
        } else if tree.dirs.contains(&path) || path.parent().is_none() {
            Ok(EntryKind::Dir)
        } else {
            Err(not_found(&path))
        }
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let path = normalise(path);
        let tree = self.tree();
        if !tree.dirs.contains(&path) && path.parent().is_some() {
            return Err(not_found(&path));
        }
        let child = |entry: &Path| {
            (entry.parent() == Some(path.as_path()))
                .then(|| entry.file_name())
                .flatten()
                .map(|name| name.to_string_lossy().into_owned())
        };
        let mut entries: Vec<DirEntry> = tree
            .files
            .keys()
            .filter_map(|file| child(file))
            .map(|name| DirEntry {
                name,
                kind: EntryKind::File,
                symlink: false,
            })
            .collect();
        entries.extend(
            tree.dirs
                .iter()
                .filter_map(|dir| child(dir))
                .map(|name| DirEntry {
                    name,
                    kind: EntryKind::Dir,
                    symlink: false,
                }),
        );
        Ok(entries)
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        normalise(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_fs_writes_lists_renames_and_removes() {
        let fs = MemoryFs::new();
        fs.write("/ws/objects/rules/a.yaml", "a: 1\n");
        fs.create_dir("/ws/objects/threats");
        assert!(fs.is_dir(Path::new("/ws/objects")));
        assert!(fs.is_file(Path::new("/ws/objects/rules/a.yaml")));
        let mut names: Vec<String> = fs
            .read_dir(Path::new("/ws/objects"))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, ["rules", "threats"]);
        assert!(fs.rename("/ws/objects/rules", "/ws/objects/detections"));
        assert!(fs.is_file(Path::new("/ws/objects/detections/a.yaml")));
        assert!(!fs.is_dir(Path::new("/ws/objects/rules")));
        assert!(!fs.rename("/ws/nothing", "/ws/else"));
        assert!(!fs.rename("/ws/objects", "/ws/objects/inner"));
        assert!(fs.rename("/ws/objects/detections/a.yaml", "/ws/b.yaml"));
        assert_eq!(fs.read(Path::new("/ws/b.yaml")).unwrap(), b"a: 1\n");
        assert_eq!(fs.reads()[Path::new("/ws/b.yaml")], 1);
        fs.reset_reads();
        assert!(fs.reads().is_empty());
        assert!(fs.remove("/ws/objects"));
        assert!(!fs.remove("/ws/objects"));
        assert_eq!(
            fs.read(Path::new("/ws/objects")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        fs.create_dir("/ws/d");
        assert_eq!(
            fs.read(Path::new("/ws/d")).unwrap_err().kind(),
            io::ErrorKind::IsADirectory
        );
        assert!(fs.read_dir(Path::new("/ws/none")).is_err());
        assert_eq!(
            fs.resolve(Path::new("/ws/a/../b/./c")),
            PathBuf::from("/ws/b/c")
        );
    }

    #[test]
    fn os_fs_resolves_paths_that_do_not_exist_yet() {
        let dir = std::env::temp_dir().join(format!("opentide-ws-fs-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::fs::write(dir.join("a/f.yaml"), "x: 1\n").unwrap();
        let fs = OsFs;
        let resolved = fs.resolve(&dir.join("a/../a/missing/x.yaml"));
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("a/missing/x.yaml"));
        assert_eq!(fs.kind(&dir.join("a")).unwrap(), EntryKind::Dir);
        assert_eq!(fs.kind(&dir.join("a/f.yaml")).unwrap(), EntryKind::File);
        assert_eq!(fs.read(&dir.join("a/f.yaml")).unwrap(), b"x: 1\n");
        let entries = fs.read_dir(&dir.join("a")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "f.yaml");
        assert!(!entries[0].symlink);
        assert!(fs.kind(&dir.join("nothing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
