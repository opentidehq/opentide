//! Writing a phase's files, and recording what it wrote.
//!
//! [`write_all`] writes [`Output`]s in parallel (rayon), each folder created
//! as needed. [`Changes`] is how a phase makes and reports its files: it
//! stages them, writes them only when the phase commits ([`Changes::commit`]),
//! and records every path it wrote and every path it removed, as the run did
//! it, not as a scan of the folders finds them afterwards, so a file something
//! else changes during the run is not counted. Rewriting a file with the same
//! bytes counts as written.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
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

/// A change a phase asked for, made when it [commits](Changes::commit).
#[derive(Debug, Clone)]
enum Pending {
    Write(Output),
    Remove(PathBuf),
}

/// The files a phase writes and removes, each path once.
///
/// Nothing touches the disk until [`Changes::commit`]: a phase that fails,
/// or never commits, leaves the files of the previous run as they were. The
/// commit writes every file into a staging folder beside the output first,
/// and only when all of them are written moves each into place with a rename,
/// which replaces a file whole (on Windows too). A run cut off while it moves
/// them leaves some files of the new run and the rest of the old one, but
/// never a half-written file.
///
/// The folders are not swapped whole: an output folder also holds files the
/// generator keeps (hand-written pages, a folder's `README.md`), Windows
/// cannot rename over a folder that is not empty, and a file open in another
/// program would stop a folder's rename.
#[derive(Debug, Clone, Default)]
pub struct Changes {
    pending: IndexMap<PathBuf, Pending>,
    written: BTreeSet<PathBuf>,
    removed: BTreeSet<PathBuf>,
}

impl Changes {
    /// Stages `outputs`: a later output of a path replaces an earlier one.
    ///
    /// # Errors
    ///
    /// None while staging; the `Result` is the commit's contract (an output
    /// that could not be written fails the phase).
    pub fn write_all(&mut self, outputs: &[Output]) -> Result<(), (PathBuf, io::Error)> {
        for output in outputs {
            let key = lexical(&output.path);
            self.pending.shift_remove(&key);
            self.pending.insert(key, Pending::Write(output.clone()));
        }
        Ok(())
    }

    /// Stages the removal of the file `path`; a file that is not there, and
    /// not staged to be written, is not recorded.
    ///
    /// # Errors
    ///
    /// None while staging; see [`Changes::write_all`].
    pub fn remove(&mut self, path: &Path) -> Result<(), (PathBuf, io::Error)> {
        let key = lexical(path);
        let staged = matches!(self.pending.get(&key), Some(Pending::Write(_)));
        if !staged && std::fs::symlink_metadata(path).is_err() {
            return Ok(());
        }
        self.pending.shift_remove(&key);
        self.pending
            .insert(key, Pending::Remove(path.to_path_buf()));
        Ok(())
    }

    /// Stages the removal of each of `paths` ([`Changes::remove`]), in order.
    ///
    /// # Errors
    ///
    /// None while staging; see [`Changes::write_all`].
    pub fn remove_all(&mut self, paths: &[PathBuf]) -> Result<(), (PathBuf, io::Error)> {
        paths.iter().try_for_each(|path| self.remove(path))
    }

    /// Makes the staged changes: every file written into a staging folder,
    /// then moved into place, then the removals. Until every file is staged,
    /// nothing in place changes.
    ///
    /// # Errors
    ///
    /// The first file that could not be written, moved or removed, with its
    /// path. The staging folder is removed either way.
    pub fn commit(&mut self) -> Result<(), (PathBuf, io::Error)> {
        let pending = std::mem::take(&mut self.pending);
        let outputs: Vec<&Output> = pending
            .values()
            .filter_map(|change| match change {
                Pending::Write(output) => Some(output),
                Pending::Remove(_) => None,
            })
            .collect();
        if !outputs.is_empty() {
            let staging = Staging::new(&outputs)?;
            let staged = staging.stage(&outputs);
            let moved = staged.and_then(|()| staging.promote(&outputs));
            drop(staging);
            moved?;
        }
        for change in pending.values() {
            match change {
                Pending::Write(output) => {
                    let path = resolved(&output.path);
                    self.removed.remove(&path);
                    self.written.insert(path);
                }
                Pending::Remove(path) => match std::fs::remove_file(path) {
                    Ok(()) => {
                        let shown = resolved(path);
                        self.written.remove(&shown);
                        self.removed.insert(shown);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err((path.clone(), error)),
                },
            }
        }
        Ok(())
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

/// The folder a commit writes its files into before it moves them: a hidden
/// sibling of the folder that holds them all, so it is on the same volume and
/// never inside a folder a pipeline publishes. Removed when dropped.
struct Staging {
    /// The folder every output is under.
    base: PathBuf,
    /// The staging folder.
    dir: PathBuf,
}

impl Staging {
    fn new(outputs: &[&Output]) -> Result<Self, (PathBuf, io::Error)> {
        let mut base = outputs
            .first()
            .and_then(|output| lexical(&output.path).parent().map(Path::to_path_buf))
            .unwrap_or_default();
        for output in outputs {
            let path = lexical(&output.path);
            while !path.starts_with(&base) {
                if !base.pop() {
                    break;
                }
            }
        }
        let name = base
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let unique = format!(
            ".{name}.opentide-staging-{}-{}",
            std::process::id(),
            STAGINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        // At a volume's root there is no sibling: stage inside it.
        let dir = match base.parent() {
            Some(parent) if !name.is_empty() => parent.join(unique),
            _ => base.join(unique),
        };
        std::fs::create_dir_all(&dir).map_err(|error| (dir.clone(), error))?;
        Ok(Self { base, dir })
    }

    /// Where `output` is staged.
    fn staged(&self, output: &Output) -> PathBuf {
        let path = lexical(&output.path);
        self.dir
            .join(path.strip_prefix(&self.base).unwrap_or(&path))
    }

    /// Writes every output into the staging folder, in parallel.
    fn stage(&self, outputs: &[&Output]) -> Result<(), (PathBuf, io::Error)> {
        outputs.par_iter().try_for_each(|output| {
            let staged = self.staged(output);
            if let Some(parent) = staged.parent() {
                std::fs::create_dir_all(parent).map_err(|error| (output.path.clone(), error))?;
            }
            fail_point(&output.path)?;
            std::fs::write(&staged, &output.bytes).map_err(|error| (output.path.clone(), error))
        })
    }

    /// Moves every staged file into place, in order.
    fn promote(&self, outputs: &[&Output]) -> Result<(), (PathBuf, io::Error)> {
        for output in outputs {
            let target = &output.path;
            if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|error| (parent.to_path_buf(), error))?;
            }
            // A symbolic link is written through, as before, not replaced.
            if std::fs::symlink_metadata(target).is_ok_and(|meta| meta.file_type().is_symlink()) {
                std::fs::write(target, &output.bytes).map_err(|error| (target.clone(), error))?;
                continue;
            }
            let staged = self.staged(output);
            if std::fs::rename(&staged, target).is_err() {
                // Another volume under the output (a mount): a copy beside
                // the target, then a rename on its own volume.
                let beside = beside(target);
                let moved =
                    std::fs::copy(&staged, &beside).and_then(|_| std::fs::rename(&beside, target));
                if let Err(error) = moved {
                    let _ = std::fs::remove_file(&beside);
                    return Err((target.clone(), error));
                }
            }
        }
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Tells staging folders of one process apart.
static STAGINGS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A temporary name beside `path`, for the copy a rename across volumes needs.
fn beside(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(
        ".{name}.opentide-{}-{}.tmp",
        std::process::id(),
        STAGINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}

/// `path` absolute, with `.` and `..` taken out by its text: the key two
/// spellings of one output share.
fn lexical(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };
    let mut clean = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                clean.pop();
            }
            other => clean.push(other.as_os_str()),
        }
    }
    clean
}

/// A failure injected while a test stages `path`: set by
/// [`fail_staging_of`] in this thread's tests only.
#[cfg(test)]
fn fail_point(path: &Path) -> Result<(), (PathBuf, io::Error)> {
    let failing = FAIL_STAGING
        .lock()
        .ok()
        .and_then(|name| name.clone())
        .is_some_and(|name| path.file_name().is_some_and(|file| file == name.as_str()));
    if failing {
        return Err((path.to_path_buf(), io::Error::other("injected failure")));
    }
    Ok(())
}

#[cfg(not(test))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the test build's twin injects a failure here"
)]
fn fail_point(_path: &Path) -> Result<(), (PathBuf, io::Error)> {
    Ok(())
}

#[cfg(test)]
static FAIL_STAGING: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Makes staging a file named `name` fail, in this process's tests.
#[cfg(test)]
fn fail_staging_of(name: Option<&str>) {
    if let Ok(mut failing) = FAIL_STAGING.lock() {
        *failing = name.map(str::to_owned);
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
        changes.commit().unwrap();
        // What something else changes or removes during the run is not the run's.
        std::fs::write(root.join("unrelated"), "changed by someone else").unwrap();
        std::fs::write(root.join("new elsewhere"), "x").unwrap();
        std::fs::remove_file(root.join("kept")).unwrap();
        changes
            .remove_all(&[root.join("gone"), root.join("never there")])
            .unwrap();
        changes.commit().unwrap();
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
        changes.commit().unwrap();
        changes
            .write_all(&[
                Output::text(same.clone(), "abc".into()),
                Output::text(page.clone(), "new".into()),
            ])
            .unwrap();
        changes.commit().unwrap();
        assert_eq!(changes.written(), [page.clone(), same]);
        assert!(changes.removed().is_empty());
        changes.remove(&page).unwrap();
        changes.commit().unwrap();
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

    /// The files of `dir`, by path from it, with their text.
    fn tree(dir: &Path) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let mut folders = vec![dir.to_path_buf()];
        while let Some(folder) = folders.pop() {
            for entry in std::fs::read_dir(&folder).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    folders.push(path);
                } else {
                    let name = path
                        .strip_prefix(dir)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    found.push((name, std::fs::read_to_string(&path).unwrap()));
                }
            }
        }
        found.sort();
        found
    }

    #[test]
    fn nothing_changes_on_disk_until_the_phase_commits() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let out = root.join("docs");
        std::fs::create_dir_all(out.join("rules")).unwrap();
        std::fs::write(out.join("rules/a.md"), "old a").unwrap();
        std::fs::write(out.join("rules/stale.md"), "old stale").unwrap();
        let before = tree(&root);
        let mut changes = Changes::default();
        changes
            .write_all(&[
                Output::text(out.join("rules/a.md"), "new a".into()),
                Output::text(out.join("rules/b.md"), "new b".into()),
            ])
            .unwrap();
        changes.remove(&out.join("rules/stale.md")).unwrap();
        // A phase that fails after staging drops its changes uncommitted.
        drop(changes);
        assert_eq!(tree(&root), before);
    }

    #[test]
    fn a_commit_that_fails_midway_leaves_the_previous_output_and_no_staging() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let out = root.join("docs");
        std::fs::create_dir_all(out.join("rules")).unwrap();
        std::fs::write(out.join("rules/a.md"), "old a").unwrap();
        std::fs::write(out.join("rules/stale.md"), "old stale").unwrap();
        std::fs::write(out.join("notes.md"), "hand-written").unwrap();
        let before = tree(&root);
        let outputs: Vec<Output> = (0..40)
            .map(|n| Output::text(out.join(format!("rules/p{n}.md")), format!("page {n}")))
            .chain([
                Output::text(out.join("rules/a.md"), "new a".into()),
                Output::text(out.join("rules/zz-commit-fails-here.md"), "x".into()),
            ])
            .collect();
        let mut changes = Changes::default();
        changes.write_all(&outputs).unwrap();
        changes.remove(&out.join("rules/stale.md")).unwrap();
        fail_staging_of(Some("zz-commit-fails-here.md"));
        let failed = changes.commit();
        fail_staging_of(None);
        let (path, _) = failed.unwrap_err();
        assert_eq!(path, out.join("rules/zz-commit-fails-here.md"));
        // Every file as it was, the hand-written one kept, nothing staged left.
        assert_eq!(tree(&root), before);
        assert!(changes.written().is_empty());
        // The same changes, committed, replace the output whole.
        let mut changes = Changes::default();
        changes.write_all(&outputs).unwrap();
        changes.remove(&out.join("rules/stale.md")).unwrap();
        changes.commit().unwrap();
        let after = tree(&root);
        assert!(after.contains(&(
            "docs/rules/a.md".replace('/', std::path::MAIN_SEPARATOR_STR),
            "new a".to_owned()
        )));
        assert!(after.contains(&(
            "docs/notes.md".replace('/', std::path::MAIN_SEPARATOR_STR),
            "hand-written".to_owned()
        )));
        assert!(!out.join("rules/stale.md").exists());
        assert_eq!(after.len(), 43);
        assert_eq!(changes.removed(), [out.join("rules/stale.md")]);
    }
}
