//! A preview of the status promotion a `RELEASE` push will make (#1653,
//! smoke E13 and E15): `deploy --dry-run` and `validate query --live
//! --changed` on a push read the workspace as the push's deploy will after
//! its `status promotion` step, the promoted files read from memory over
//! the disk, so the plan and the live check see the promoted status and the
//! tenants it routes the rules to. Nothing is written.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::Owned;
use opentide_compile::strategy::StatusStrategy;
use opentide_workspace::fs::{DirEntry, EntryKind, FileSystem, Stamp};
use opentide_workspace::{OsFs, RootOptions, Workspace};

use super::deploy_promote::{self, Promotion};
use crate::env::Env;

/// The disk, with some files' bytes replaced by others held in memory.
#[derive(Debug, Default)]
pub struct Overlay {
    files: HashMap<PathBuf, Vec<u8>>,
}

impl Overlay {
    /// The disk with `files` (path, bytes) read from memory.
    pub fn new(files: impl IntoIterator<Item = (PathBuf, Vec<u8>)>) -> Self {
        Self {
            files: files
                .into_iter()
                .map(|(path, bytes)| (OsFs.resolve(&path), bytes))
                .collect(),
        }
    }

    fn held(&self, path: &Path) -> Option<&Vec<u8>> {
        self.files.get(&OsFs.resolve(path))
    }
}

impl FileSystem for Overlay {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        match self.held(path) {
            Some(bytes) => Ok(bytes.clone()),
            None => OsFs.read(path),
        }
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        OsFs.kind(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        OsFs.read_dir(path)
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        OsFs.resolve(path)
    }

    fn stamp(&self, path: &Path) -> io::Result<Stamp> {
        match self.held(path) {
            Some(bytes) => Ok(Stamp::of_bytes(bytes)),
            None => OsFs.stamp(path),
        }
    }
}

/// Whether a run with `runs` would promote before it deploys: a `RELEASE`
/// run on a push in CI that reads the push's changes (no `--all`, `--uuid`
/// or `--file`), as `deploy` decides (`deploy_send::promotes`).
pub fn applies(runs: &[StatusStrategy], reads_changes: bool, env: &Env) -> bool {
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    let ci = opentide_compile::git::ci(&lookup);
    runs.contains(&StatusStrategy::Release)
        && reads_changes
        && ci != opentide_compile::git::Ci::Local
        && !opentide_compile::git::is_change_request(ci, &lookup)
}

/// The workspace as the push's deploy will read it after promoting
/// `changed` (every rule file of `local` instead when `debug`), opened with
/// `options`, and how many files the promotion rewrites; `None` when it
/// rewrites none or would stop the run (the deploy reports that itself).
///
/// # Errors
///
/// The workspace does not open through the overlay.
pub fn promoted_workspace(
    owned: &Owned,
    options: RootOptions,
    changed: &[PathBuf],
    local: &[PathBuf],
    debug: bool,
) -> Result<Option<(Workspace, usize, String)>, String> {
    let settings = opentide_compile::promotion::Settings::new(&owned.config, &owned.statuses);
    let promotion = Promotion {
        settings: &settings,
        changed,
        local,
        debug,
    };
    let Ok(files) = deploy_promote::preview(&promotion) else {
        return Ok(None);
    };
    if files.is_empty() {
        return Ok(None);
    }
    let count = files.len();
    let target = settings.target.clone().unwrap_or_default();
    let workspace = Workspace::open(
        Arc::new(Overlay::new(files)),
        opentide_workspace::Options { roots: options },
    )
    .map_err(|error| error.to_string())?;
    Ok(Some((workspace, count, target)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_overlay_reads_its_files_from_memory_and_the_rest_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let held = dir.path().join("held.yaml");
        let other = dir.path().join("other.yaml");
        std::fs::write(&held, "status: STAGING\n").unwrap();
        std::fs::write(&other, "status: STAGING\n").unwrap();
        let overlay = Overlay::new([(held.clone(), b"status: PRODUCTION\n".to_vec())]);
        assert_eq!(overlay.read(&held).unwrap(), b"status: PRODUCTION\n");
        assert_eq!(overlay.read(&other).unwrap(), b"status: STAGING\n");
        assert_eq!(
            overlay.stamp(&held).unwrap(),
            Stamp::of_bytes(b"status: PRODUCTION\n")
        );
        assert!(!overlay.shared());
        assert_eq!(overlay.read_dir(dir.path()).unwrap().len(), 2);
        // Nothing reached the disk.
        assert_eq!(std::fs::read(&held).unwrap(), b"status: STAGING\n");
    }

    #[test]
    fn only_a_release_push_that_reads_its_changes_promotes() {
        let push = Env::from_pairs([
            ("GITHUB_ACTIONS".to_owned(), "true".to_owned()),
            ("GITHUB_EVENT_NAME".to_owned(), "push".to_owned()),
        ]);
        let request = Env::from_pairs([
            ("GITHUB_ACTIONS".to_owned(), "true".to_owned()),
            ("GITHUB_EVENT_NAME".to_owned(), "pull_request".to_owned()),
        ]);
        let local = Env::from_pairs(Vec::<(String, String)>::new());
        let release = [StatusStrategy::Release];
        assert!(applies(&release, true, &push));
        assert!(!applies(&release, false, &push));
        assert!(!applies(&[StatusStrategy::Preview], true, &push));
        assert!(!applies(&release, true, &request));
        assert!(!applies(&release, true, &local));
    }
}
