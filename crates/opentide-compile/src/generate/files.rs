//! Writing a phase's files, and recording what it wrote.
//!
//! [`write_all`] writes [`Output`]s in parallel (rayon), each folder created
//! as needed. [`Changes`] is how a phase reports its files: every path it
//! wrote and every path it removed, as the run did it, not as a scan of the
//! folders finds them afterwards, so a file something else changes during the
//! run is not counted. Rewriting a file with the same bytes counts as written.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use super::Output;

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

/// The files a phase wrote and removed, each path once, recorded as it
/// writes and removes them.
#[derive(Debug, Clone, Default)]
pub struct Changes {
    written: BTreeSet<PathBuf>,
    removed: BTreeSet<PathBuf>,
}

impl Changes {
    /// Writes `outputs` ([`write_all`]) and records their paths.
    ///
    /// # Errors
    ///
    /// The first output that could not be written, with its path; nothing
    /// is recorded then.
    pub fn write_all(&mut self, outputs: &[Output]) -> Result<(), (PathBuf, io::Error)> {
        write_all(outputs)?;
        for output in outputs {
            let path = resolved(&output.path);
            self.removed.remove(&path);
            self.written.insert(path);
        }
        Ok(())
    }

    /// Removes the file `path` and records it; a file already gone is not
    /// recorded.
    ///
    /// # Errors
    ///
    /// Why the file could not be removed, with its path.
    pub fn remove(&mut self, path: &Path) -> Result<(), (PathBuf, io::Error)> {
        let shown = resolved(path);
        match std::fs::remove_file(path) {
            Ok(()) => {
                self.written.remove(&shown);
                self.removed.insert(shown);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err((path.to_path_buf(), error)),
        }
    }

    /// Removes each of `paths` ([`Changes::remove`]), in order.
    ///
    /// # Errors
    ///
    /// The first file that could not be removed, with its path.
    pub fn remove_all(&mut self, paths: &[PathBuf]) -> Result<(), (PathBuf, io::Error)> {
        paths.iter().try_for_each(|path| self.remove(path))
    }

    /// The files written, sorted.
    pub fn written(&self) -> Vec<PathBuf> {
        self.written.iter().cloned().collect()
    }

    /// The files removed (and not written again after), sorted.
    pub fn removed(&self) -> Vec<PathBuf> {
        self.removed.iter().cloned().collect()
    }
}

/// `path` with its folder resolved (symbolic links, `..`), so one file is
/// recorded once however it was named; the file itself may be gone.
fn resolved(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            dunce::canonicalize(parent).map_or_else(|_| path.to_path_buf(), |dir| dir.join(name))
        }
        _ => path.to_path_buf(),
    }
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
    fn written_and_removed_files_are_the_ones_the_run_named() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("kept"), "a").unwrap();
        std::fs::write(root.join("gone"), "a").unwrap();
        std::fs::write(root.join("unrelated"), "a").unwrap();
        let mut changes = Changes::default();
        changes
            .write_all(&[
                Output::text(root.join("out/b.json"), "{}\n".into()),
                Output::text(root.join("out/a.json"), "{}\n".into()),
                // Named twice, the second time through `..`: one file.
                Output::text(root.join("out/../out/a.json"), "{}\n".into()),
            ])
            .unwrap();
        // What something else changes or removes during the run is not the run's.
        std::fs::write(root.join("unrelated"), "changed by someone else").unwrap();
        std::fs::write(root.join("new elsewhere"), "x").unwrap();
        std::fs::remove_file(root.join("kept")).unwrap();
        changes
            .remove_all(&[root.join("gone"), root.join("never there")])
            .unwrap();
        let written = changes.written();
        assert_eq!(written, [root.join("out/a.json"), root.join("out/b.json")]);
        assert_eq!(changes.removed(), [root.join("gone")]);
        assert!(!root.join("gone").exists());
        assert_eq!(common_dir(&written, &root, &root).as_deref(), Some("out/"));
        assert_eq!(
            common_dir(&[root.join("out/a.json"), root.join("kept")], &root, &root).as_deref(),
            Some("./")
        );
        assert_eq!(common_dir(&[], &root, &root), None);
    }

    #[test]
    fn a_rewritten_file_counts_as_written_and_a_removed_one_written_again_is_not_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let (same, page) = (root.join("same"), root.join("page.md"));
        std::fs::write(&same, "abc").unwrap();
        std::fs::write(&page, "old").unwrap();
        let mut changes = Changes::default();
        changes.remove(&page).unwrap();
        changes
            .write_all(&[
                Output::text(same.clone(), "abc".into()),
                Output::text(page.clone(), "new".into()),
            ])
            .unwrap();
        assert_eq!(changes.written(), [page.clone(), same]);
        assert!(changes.removed().is_empty());
        changes.remove(&page).unwrap();
        assert_eq!(changes.written().len(), 1);
        assert_eq!(changes.removed(), [page]);
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
