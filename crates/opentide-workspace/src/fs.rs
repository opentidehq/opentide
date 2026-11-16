//! The filesystem a workspace is read through.
//!
//! Loading never calls `std::fs` directly: it goes through [`FileSystem`],
//! so the language server can serve its open buffers, a test can build a
//! workspace in memory ([`MemoryFs`]), and every read is counted in one
//! place. [`OsFs`] is the disk.
//!
//! The commands that change files (`validate --fix`, `lint --fix`) write
//! through [`WriteFs`]: a file is replaced only while it still holds what was
//! read, through a temporary file renamed over it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
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
    /// The entry's name, lossily decoded when it is not UTF-8: for matching
    /// suffixes and for display only.
    pub name: String,
    /// The entry's name as the filesystem gives it: the one to join onto
    /// its folder, so a name that is not UTF-8 still names the file.
    pub file_name: OsString,
    /// What it names, links followed.
    pub kind: EntryKind,
    /// Whether the entry itself is a symbolic link. A walk does not descend
    /// into a linked directory, so a link cannot make it loop.
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
    /// path exists: a path that does not exist (yet) still resolves,
    /// lexically past its last existing parent.
    fn resolve(&self, path: &Path) -> PathBuf;

    /// What `path` holds now, as cheaply as the filesystem can tell: two
    /// equal stamps mean the file did not change (`--watch`'s snapshot).
    ///
    /// # Errors
    ///
    /// The file cannot be examined.
    fn stamp(&self, path: &Path) -> io::Result<Stamp> {
        let bytes = self.read(path)?;
        Ok(Stamp::of_bytes(&bytes))
    }

    /// Whether every instance reads the same files, so a workspace opened
    /// through one may be kept warm for the next ([`crate::session`]): the
    /// disk. An in-memory tree is its own.
    fn shared(&self) -> bool {
        false
    }

    /// Whether `path` is a directory.
    fn is_dir(&self, path: &Path) -> bool {
        matches!(self.kind(path), Ok(EntryKind::Dir))
    }

    /// Whether `path` is a regular file.
    fn is_file(&self, path: &Path) -> bool {
        matches!(self.kind(path), Ok(EntryKind::File))
    }
}

/// What a file held when it was looked at: on disk its modification time
/// and size, in memory a digest of its bytes and their length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stamp {
    /// Nanoseconds since the epoch (disk) or a digest of the bytes (memory).
    pub version: u128,
    /// The size in bytes.
    pub len: u64,
}

impl Stamp {
    /// The stamp of `bytes`, by content.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        bytes.hash(&mut hasher);
        Self {
            version: u128::from(hasher.finish()),
            len: bytes.len() as u64,
        }
    }
}

/// Why a file was not written.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// It no longer holds the text the change was made from.
    #[error("it changed since it was read; run opentide validate --fix again")]
    Changed,
    /// The filesystem refused (a folder that cannot be written, a full disk).
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// The write side of a filesystem: what `validate --fix` and `lint --fix`
/// change.
pub trait WriteFs: FileSystem {
    /// Replaces the bytes of the file `path` names (its symbolic links
    /// followed, so a link keeps pointing at the file it names) with `after`,
    /// only while it still holds `before`. The new bytes go to a temporary
    /// file in the same folder, given the original's permissions, which is
    /// then renamed over it: a write that fails partway leaves the original
    /// whole.
    ///
    /// # Errors
    ///
    /// [`WriteError::Changed`] when the file no longer holds `before`;
    /// [`WriteError::Io`] when it cannot be read or written.
    fn replace(&self, path: &Path, before: &[u8], after: &[u8]) -> Result<(), WriteError>;

    /// Renames the file `from` to `to`. A rename that only changes the case
    /// of the name goes through a temporary name, which a case-insensitive
    /// filesystem needs.
    ///
    /// # Errors
    ///
    /// The rename failed.
    fn rename_file(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Whether `a` and `b` name the same file (on a case-insensitive
    /// filesystem, `Rule.yaml` and `rule.yaml` do).
    fn same_file(&self, a: &Path, b: &Path) -> bool;
}

/// The suffix of the temporary name a case-only rename passes through.
pub const CASE_RENAME_SUFFIX: &str = ".opentide-case-rename";

/// Whether `dest` exists only because it is `src` under another case
/// (`_case_only_rename`): on macOS and Windows `Phishing.yaml` and
/// `phishing.yaml` are one file.
pub fn case_only_rename(fs: &dyn WriteFs, src: &Path, dest: &Path) -> bool {
    let (Some(from), Some(to)) = (src.file_name(), dest.file_name()) else {
        return false;
    };
    let (from, to) = (from.to_string_lossy(), to.to_string_lossy());
    if from == to || from.to_lowercase() != to.to_lowercase() {
        return false;
    }
    let staged = src.with_file_name(format!("{from}{CASE_RENAME_SUFFIX}"));
    fs.kind(dest).is_ok() && fs.same_file(src, dest) && fs.kind(&staged).is_err()
}

/// The disk.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsFs;

impl FileSystem for OsFs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn shared(&self) -> bool {
        true
    }

    fn stamp(&self, path: &Path) -> io::Result<Stamp> {
        let metadata = std::fs::metadata(path)?;
        let version = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |since| since.as_nanos());
        Ok(Stamp {
            version,
            len: metadata.len(),
        })
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
            let file_name = entry.file_name();
            entries.push(DirEntry {
                name: file_name.to_string_lossy().into_owned(),
                file_name,
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
                    resolved = dunce::canonicalize(&candidate).unwrap_or(candidate);
                }
            }
        }
        resolved
    }
}

impl WriteFs for OsFs {
    fn replace(&self, path: &Path, before: &[u8], after: &[u8]) -> Result<(), WriteError> {
        let target = dunce::canonicalize(path)?;
        if std::fs::read(&target)? != before {
            return Err(WriteError::Changed);
        }
        Ok(write_atomically(&target, after)?)
    }

    fn rename_file(&self, from: &Path, to: &Path) -> io::Result<()> {
        if !case_only_rename(self, from, to) {
            return std::fs::rename(from, to);
        }
        let name = from
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let staged = from.with_file_name(format!("{name}{CASE_RENAME_SUFFIX}"));
        std::fs::rename(from, &staged)?;
        std::fs::rename(&staged, to)
    }

    fn same_file(&self, a: &Path, b: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            match (std::fs::metadata(a), std::fs::metadata(b)) {
                (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
                _ => false,
            }
        }
        #[cfg(not(unix))]
        {
            match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
        }
    }
}

/// Writes `bytes` to the file `path` names, whole or not at all: they go to
/// a temporary file of a unique name in the same folder, flushed to disk,
/// which is then renamed over `path`. A write that fails partway leaves the
/// file as it was and removes the temporary file, and two processes writing
/// the same file never share a temporary file.
///
/// A symbolic link is followed, so it keeps pointing at the file it names.
/// An existing file keeps its permissions; a new one gets the permissions
/// [`std::fs::write`] would give it. A path that names something other than
/// a regular file (`/dev/stdout`, a named pipe) is written in place, as it
/// cannot be replaced. The folder must exist.
///
/// # Errors
///
/// The folder or the file cannot be written.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let target = match settled(|| dunce::canonicalize(path)) {
        Ok(target) => target,
        Err(error) if error.kind() == io::ErrorKind::NotFound => path.to_path_buf(),
        Err(error) => return Err(error),
    };
    let existing = match settled(|| std::fs::metadata(&target)) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if existing
        .as_ref()
        .is_some_and(|metadata| !metadata.is_file())
    {
        return std::fs::write(&target, bytes);
    }
    let folder = target
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let prefix = format!(
        ".{}.",
        target
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_default()
    );
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix).suffix(".tmp");
    // A new file as `std::fs::write` creates it: 0666 less the umask, where
    // a temporary file is created owner-only.
    #[cfg(unix)]
    if existing.is_none() {
        builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o666));
    }
    // A folder the user cannot write refuses the temporary file itself.
    let mut temporary = builder.tempfile_in(folder)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    // The original's permissions; WASI has none to keep (its
    // `set_permissions` is unsupported).
    #[cfg(not(target_os = "wasi"))]
    if let Some(metadata) = existing {
        std::fs::set_permissions(temporary.path(), metadata.permissions())?;
    }
    // Dropped on an error, the temporary file is deleted.
    persist_over(temporary, &target)
}

/// Renames `temporary` over `target`.
///
/// On Windows the replace (`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`)
/// is not atomic against another writer of the same file: while one rename
/// is replacing the target, or a reader holds it open, a second one answers
/// `ERROR_ACCESS_DENIED`, `ERROR_SHARING_VIOLATION` or `ERROR_LOCK_VIOLATION`
/// and succeeds a moment later (the temporary file is whole and still ours).
/// Those, and only those, are tried again for a bounded time; every other
/// error, and a read-only target (which stays denied), is returned at once.
/// Elsewhere `rename` replaces atomically and there is nothing to retry.
fn persist_over(temporary: tempfile::NamedTempFile, target: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        temporary
            .persist(target)
            .map(drop)
            .map_err(|failed| failed.error)
    }
    #[cfg(windows)]
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut temporary = temporary;
        loop {
            match temporary.persist(target) {
                Ok(_) => return Ok(()),
                Err(failed)
                    if replace_may_succeed_later(&failed.error, target)
                        && std::time::Instant::now() < deadline =>
                {
                    temporary = failed.file;
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(failed) => return Err(failed.error),
            }
        }
    }
}

/// Whether `error` from replacing `target` is one Windows clears by itself.
#[cfg(windows)]
fn replace_may_succeed_later(error: &io::Error, target: &Path) -> bool {
    clears_by_itself(error)
        && !std::fs::metadata(target).is_ok_and(|metadata| metadata.permissions().readonly())
}

/// Whether `error` is one Windows answers while another writer's replace of
/// the same file is under way (see [`persist_over`]).
#[cfg(windows)]
fn clears_by_itself(error: &io::Error) -> bool {
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    matches!(
        error.raw_os_error(),
        Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
    )
}

/// `look` at the target of a write. On Windows, while another writer's
/// replace of that file is under way, the file being replaced cannot be
/// opened for a moment (it answers as [`clears_by_itself`] says): the look
/// is tried again for a bounded time, as the replace itself is. Elsewhere it
/// runs once.
fn settled<T>(mut look: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    #[cfg(windows)]
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match look() {
                Err(error) if clears_by_itself(&error) && std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                done => return done,
            }
        }
    }
    #[cfg(not(windows))]
    look()
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

impl WriteFs for MemoryFs {
    fn replace(&self, path: &Path, before: &[u8], after: &[u8]) -> Result<(), WriteError> {
        let path = normalise(path);
        let mut tree = self.tree_mut();
        match tree.files.get_mut(&path) {
            Some(bytes) if bytes.as_slice() == before => {
                *bytes = after.to_vec();
                Ok(())
            }
            Some(_) => Err(WriteError::Changed),
            None => Err(WriteError::Io(not_found(&path))),
        }
    }

    fn rename_file(&self, from: &Path, to: &Path) -> io::Result<()> {
        if self.is_file(from) && self.rename(from, to) {
            Ok(())
        } else {
            Err(not_found(from))
        }
    }

    fn same_file(&self, a: &Path, b: &Path) -> bool {
        normalise(a) == normalise(b) && self.kind(a).is_ok()
    }
}

impl FileSystem for MemoryFs {
    fn stamp(&self, path: &Path) -> io::Result<Stamp> {
        let path = normalise(path);
        let tree = self.tree();
        tree.files
            .get(&path)
            .map(|bytes| Stamp::of_bytes(bytes))
            .ok_or_else(|| not_found(&path))
    }

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
                .map(std::ffi::OsStr::to_os_string)
        };
        let mut entries: Vec<DirEntry> = tree
            .files
            .keys()
            .filter_map(|file| child(file))
            .map(|file_name| DirEntry {
                name: file_name.to_string_lossy().into_owned(),
                file_name,
                kind: EntryKind::File,
                symlink: false,
            })
            .collect();
        entries.extend(
            tree.dirs
                .iter()
                .filter_map(|dir| child(dir))
                .map(|file_name| DirEntry {
                    name: file_name.to_string_lossy().into_owned(),
                    file_name,
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
    fn memory_fs_replaces_only_what_it_still_holds() {
        let fs = MemoryFs::new();
        fs.write("/w/a.yaml", "a: 1\n");
        let stamp = fs.stamp(Path::new("/w/a.yaml")).unwrap();
        assert!(matches!(
            fs.replace(Path::new("/w/a.yaml"), b"a: 2\n", b"a: 3\n"),
            Err(WriteError::Changed)
        ));
        fs.replace(Path::new("/w/a.yaml"), b"a: 1\n", b"a: 3\n")
            .unwrap();
        assert_eq!(fs.read(Path::new("/w/a.yaml")).unwrap(), b"a: 3\n");
        assert_ne!(fs.stamp(Path::new("/w/a.yaml")).unwrap(), stamp);
        assert!(matches!(
            fs.replace(Path::new("/w/none.yaml"), b"", b""),
            Err(WriteError::Io(_))
        ));
        fs.rename_file(Path::new("/w/a.yaml"), Path::new("/w/b.yaml"))
            .unwrap();
        assert!(fs.is_file(Path::new("/w/b.yaml")));
        assert!(
            fs.rename_file(Path::new("/w/a.yaml"), Path::new("/w/c.yaml"))
                .is_err()
        );
        assert!(fs.same_file(Path::new("/w/b.yaml"), Path::new("/w/./b.yaml")));
        assert!(!fs.same_file(Path::new("/w/b.yaml"), Path::new("/w/B.yaml")));
        assert!(!case_only_rename(
            &fs,
            Path::new("/w/b.yaml"),
            Path::new("/w/B.yaml")
        ));
    }

    #[test]
    fn os_fs_replaces_through_a_temporary_file_keeping_the_mode_and_links() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("rule.yaml");
        std::fs::write(&file, "severity: high\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        #[cfg(unix)]
        let link = {
            let link = dir.path().join("link.yaml");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            link
        };
        #[cfg(not(unix))]
        let link = file.clone();
        let fs = OsFs;
        let stamp = fs.stamp(&file).unwrap();
        assert_eq!(stamp.len, 15);
        // Saved since it was read: left alone.
        assert!(matches!(
            fs.replace(&link, b"severity: low\n", b"severity: High\n"),
            Err(WriteError::Changed)
        ));
        fs.replace(&link, b"severity: high\n", b"severity: High\n")
            .unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"severity: High\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o640);
        }
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".rule.yaml."))
            .collect();
        assert!(names.is_empty(), "{names:?}");
        let moved = dir.path().join("moved.yaml");
        fs.rename_file(&file, &moved).unwrap();
        assert!(moved.is_file() && !file.exists());
        assert!(fs.same_file(&moved, &moved));
        assert!(!fs.same_file(&moved, &dir.path().join("none.yaml")));
        assert!(matches!(
            fs.replace(&dir.path().join("none.yaml"), b"", b""),
            Err(WriteError::Io(_))
        ));
    }

    #[test]
    fn an_atomic_write_replaces_the_file_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        write_atomically(&path, b"one").unwrap();
        write_atomically(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        // A missing folder is an error, and nothing is written.
        assert!(write_atomically(&dir.path().join("none/x"), b"x").is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn an_atomic_write_takes_a_temporary_name_no_other_writer_has() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        // The fixed names earlier writers used are taken (by folders, which a
        // file cannot be written over): the write does not need them.
        for taken in ["ledger.jsonl.tmp", ".ledger.jsonl.tmp"] {
            std::fs::create_dir(dir.path().join(taken)).unwrap();
        }
        write_atomically(&path, b"x").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        // Writers at once: each write lands whole, and none fails on
        // another's temporary file.
        std::thread::scope(|scope| {
            for writer in 0..8u8 {
                let path = &path;
                scope.spawn(move || {
                    for _ in 0..20 {
                        write_atomically(path, &[writer; 64]).unwrap();
                    }
                });
            }
        });
        let last = std::fs::read(&path).unwrap();
        assert_eq!(last.len(), 64);
        assert!(last.iter().all(|byte| *byte == last[0]));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    /// A reader holding the file open without sharing delete (a virus
    /// scanner, an editor) blocks the replace on Windows for a moment: the
    /// write waits for it rather than failing.
    #[cfg(windows)]
    #[test]
    fn an_atomic_write_waits_for_a_reader_to_let_go_of_the_file() {
        use std::os::windows::fs::OpenOptionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        std::fs::write(&path, b"old").unwrap();
        // FILE_SHARE_READ | FILE_SHARE_WRITE, not FILE_SHARE_DELETE.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0b11)
            .open(&path)
            .unwrap();
        let reader = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            drop(held);
        });
        write_atomically(&path, b"new").unwrap();
        reader.join().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// The temporary file is created owner-only: a rule committed as 0644
    /// must not come back owner-only (#987), and a new file is created as
    /// `std::fs::write` creates one.
    #[cfg(unix)]
    #[test]
    fn an_atomic_write_keeps_the_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        for kept in [0o644, 0o640, 0o755] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("r.yaml");
            std::fs::write(&path, "x").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(kept)).unwrap();
            write_atomically(&path, b"y").unwrap();
            assert_eq!(mode(&path), kept, "{kept:o}");
            assert_eq!(std::fs::read(&path).unwrap(), b"y");
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("plain"), "x").unwrap();
        write_atomically(&dir.path().join("atomic"), b"x").unwrap();
        assert_eq!(
            mode(&dir.path().join("atomic")),
            mode(&dir.path().join("plain"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_atomic_write_through_a_link_replaces_the_file_it_names() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.md");
        let link = dir.path().join("link.md");
        std::fs::write(&target, "old").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_atomically(&link, b"new").unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
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
