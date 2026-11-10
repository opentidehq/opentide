//! Writing a phase's files, and counting what it wrote.
//!
//! [`write_all`] writes [`Output`]s in parallel (rayon), each folder created
//! as needed. [`Snapshot`] is how a phase reports the files it wrote, as the
//! oracle's `WrittenFiles` does (`cli/services/generation.py`): every file
//! under the watched roots with its modification time and size, before and
//! after; a file whose stamp changed was written, one that is gone was
//! removed. Rewriting a file with the same bytes counts as written.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rayon::prelude::*;

use super::Output;

/// Folders never scanned for written files: version control, environments, caches.
const SKIPPED_DIRS: [&str; 10] = [
    ".git",
    ".hg",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
];

/// Writes every output, in parallel. Where two outputs name the same path
/// (two exports configured to one file name), the later one is written, as
/// writing them one after another leaves it.
///
/// # Errors
///
/// The first output that could not be written, with its path.
pub fn write_all(outputs: &[Output]) -> Result<(), (PathBuf, io::Error)> {
    last_per_path(outputs).par_iter().try_for_each(|output| {
        if let Some(parent) = output.path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| (parent.to_path_buf(), error))?;
        }
        std::fs::write(&output.path, &output.bytes).map_err(|error| (output.path.clone(), error))
    })
}

/// `outputs` without those a later output of the same path replaces, in order.
fn last_per_path(outputs: &[Output]) -> Vec<&Output> {
    let mut last: std::collections::HashMap<&Path, usize> = std::collections::HashMap::new();
    for (position, output) in outputs.iter().enumerate() {
        last.insert(output.path.as_path(), position);
    }
    outputs
        .iter()
        .enumerate()
        .filter(|(position, output)| last[output.path.as_path()] == *position)
        .map(|(_, output)| output)
        .collect()
}

/// A file's stamp: modification time and size.
type Stamp = (Option<SystemTime>, u64);

/// The files under some roots, with their stamps.
#[derive(Debug, Clone)]
pub struct Snapshot {
    roots: Vec<PathBuf>,
    files: BTreeMap<PathBuf, Stamp>,
}

impl Snapshot {
    /// The files under `roots` now (a root that is no folder holds none).
    pub fn take(roots: &[PathBuf]) -> Self {
        let mut unique: Vec<PathBuf> = Vec::new();
        for root in roots {
            let root = dunce::canonicalize(root).unwrap_or_else(|_| root.clone());
            if !unique.contains(&root) {
                unique.push(root);
            }
        }
        let files = scan(&unique);
        Self {
            roots: unique,
            files,
        }
    }

    /// The files written and the files removed since, each sorted.
    pub fn changes(&self) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let after = scan(&self.roots);
        let written = after
            .iter()
            .filter(|(path, stamp)| self.files.get(*path) != Some(stamp))
            .map(|(path, _)| path.clone())
            .collect();
        let removed = self
            .files
            .keys()
            .filter(|path| !after.contains_key(*path))
            .cloned()
            .collect();
        (written, removed)
    }
}

fn scan(roots: &[PathBuf]) -> BTreeMap<PathBuf, Stamp> {
    let mut seen = BTreeMap::new();
    let mut pending: Vec<PathBuf> = roots.iter().filter(|root| root.is_dir()).cloned().collect();
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if !SKIPPED_DIRS.iter().any(|skip| entry.file_name() == *skip) {
                    pending.push(entry.path());
                }
            } else if kind.is_file()
                && let Ok(metadata) = entry.metadata()
            {
                seen.insert(entry.path(), (metadata.modified().ok(), metadata.len()));
            }
        }
    }
    seen
}

/// The folder that holds every path, as a reader sees it
/// (`.opentide/exports/`): relative to `cwd` when inside it, else to
/// `workspace`, else whole; a folder ends with `/`.
pub fn common_dir(paths: &[PathBuf], cwd: &Path, workspace: &Path) -> Option<String> {
    let mut common: PathBuf = paths.first()?.parent()?.to_path_buf();
    for path in &paths[1..] {
        let parent = path.parent().unwrap_or(path);
        while !parent.starts_with(&common) {
            if !common.pop() {
                break;
            }
        }
    }
    Some(shown(&common, cwd, workspace))
}

/// `path` as the CLI shows it (`display_path`).
pub fn shown(path: &Path, cwd: &Path, workspace: &Path) -> String {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let resolved = dunce::canonicalize(&absolute).unwrap_or_else(|_| absolute.clone());
    let mut text = posix(&absolute);
    for base in [cwd, workspace] {
        let base = dunce::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
        if let Ok(relative) = resolved.strip_prefix(&base) {
            text = if relative.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                posix(relative)
            };
            break;
        }
    }
    if absolute.is_dir() && !text.ends_with('/') {
        text.push('/');
    }
    text
}

fn posix(path: &Path) -> String {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
        .replacen("//", "/", 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_and_removed_files_are_found_by_their_stamps() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("kept"), "a").unwrap();
        std::fs::write(root.join("gone"), "a").unwrap();
        std::fs::create_dir(root.join(".git")).unwrap();
        let snapshot = Snapshot::take(&[root.clone(), root.clone()]);
        write_all(&[
            Output::text(root.join("out/a.json"), "{}\n".into()),
            Output::text(root.join("out/b.json"), "{}\n".into()),
        ])
        .unwrap();
        std::fs::write(root.join(".git/ignored"), "x").unwrap();
        std::fs::remove_file(root.join("gone")).unwrap();
        let (written, removed) = snapshot.changes();
        assert_eq!(written, [root.join("out/a.json"), root.join("out/b.json")]);
        assert_eq!(removed, [root.join("gone")]);
        assert_eq!(common_dir(&written, &root, &root).as_deref(), Some("out/"));
        assert_eq!(
            common_dir(&[root.join("out/a.json"), root.join("kept")], &root, &root).as_deref(),
            Some("./")
        );
        assert_eq!(common_dir(&[], &root, &root), None);
    }

    #[test]
    fn a_rewritten_file_counts_as_written() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let (same, changed, untouched) = (root.join("same"), root.join("changed"), root.join("x"));
        for path in [&same, &changed, &untouched] {
            std::fs::write(path, "abc").unwrap();
        }
        // Stamps differ by modification time alone: set an old one.
        let old = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        for path in [&same, &changed, &untouched] {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        let snapshot = Snapshot::take(std::slice::from_ref(&root));
        write_all(&[
            Output::text(same.clone(), "abc".into()),
            Output::text(changed.clone(), "xyz".into()),
        ])
        .unwrap();
        let (written, removed) = snapshot.changes();
        assert_eq!(written, [changed, same]);
        assert!(removed.is_empty());
    }

    #[test]
    fn the_last_output_of_a_path_wins() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let path = root.join("export.json");
        let outputs = [
            Output::text(path.clone(), "a much longer first export\n".into()),
            Output::text(root.join("other.json"), "{}\n".into()),
            Output::text(path.clone(), "second\n".into()),
        ];
        let kept: Vec<&Output> = last_per_path(&outputs);
        assert_eq!(kept, [&outputs[1], &outputs[2]]);
        write_all(&outputs).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");
    }
}
