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

/// Whether the run is one that could promote before it deploys: a `RELEASE`
/// run on a push in CI that reads the push's changes (no `--all`, `--uuid`
/// or `--file`), as `deploy` decides (`deploy_send::promotes`).
fn candidate(
    runs: &[StatusStrategy],
    reads_changes: bool,
    env: &Env,
) -> Option<opentide_compile::git::Ci> {
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    let ci = opentide_compile::git::ci(&lookup);
    (runs.contains(&StatusStrategy::Release)
        && reads_changes
        && ci != opentide_compile::git::Ci::Local
        && !opentide_compile::git::is_change_request(ci, &lookup))
    .then_some(ci)
}

/// Whether a run with `runs` would promote before it deploys: a candidate
/// run (see [`candidate`]) that is a push to the default branch. A push to
/// another branch, a tag, or a default branch the CI environment does not
/// say promotes nothing.
pub fn applies(runs: &[StatusStrategy], reads_changes: bool, env: &Env) -> bool {
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    candidate(runs, reads_changes, env)
        .is_some_and(|ci| opentide_compile::git::default_branch_push(ci, &lookup) == Some(true))
}

/// The warning for a run that would promote but for a branch the CI
/// environment does not say: the promotion is skipped, and how to fix it.
/// `None` when promotion is off (`enabled` false), which the run says nothing
/// about, or the run is not a candidate or its branch is known.
pub fn undetermined_warning(
    runs: &[StatusStrategy],
    reads_changes: bool,
    env: &Env,
    enabled: bool,
) -> Option<String> {
    use opentide_compile::git::{DEFAULT_BRANCH_ENV, default_branch_push, pushed_branch};
    if !enabled {
        return None;
    }
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    let ci = candidate(runs, reads_changes, env)?;
    if default_branch_push(ci, &lookup).is_some() {
        return None;
    }
    let cause = if pushed_branch(ci, &lookup).is_none() {
        "the branch this push is to could not be determined (the CI environment does not name it)"
    } else {
        "the repository's default branch could not be determined"
    };
    Some(format!(
        "status promotion skipped: {cause}, so the push is not known to be to the default \
         branch. Set {DEFAULT_BRANCH_ENV} to the default branch's name, or regenerate the \
         pipeline (`opentide setup ci`)"
    ))
}

/// What the push's deploy will do at its status promotion, as a preview
/// reads it.
pub enum Preview {
    /// The promotion rewrites no file.
    Nothing,
    /// The workspace as the deploy will read it after promoting, the files
    /// it rewrites, the canonical UUIDs of their rules, and the target.
    Promoted {
        /// The workspace, the promoted files read from memory.
        workspace: Box<Workspace>,
        /// The files the promotion rewrites.
        files: Vec<PathBuf>,
        /// Their rules' canonical UUIDs.
        uuids: Vec<String>,
        /// The status they are promoted to.
        target: String,
    },
    /// The promotion would stop the run: what it says.
    Stops(String),
}

/// The workspace as the push's deploy will read it after promoting
/// `changed` (every rule file of `local` instead when `debug`), opened with
/// `options`.
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
) -> Result<Preview, String> {
    let settings = opentide_compile::promotion::Settings::new(&owned.config, &owned.statuses);
    let promotion = Promotion {
        settings: &settings,
        changed,
        local,
        debug,
    };
    let planned = match deploy_promote::preview(&promotion) {
        Ok(planned) => planned,
        Err(stop) => return Ok(Preview::Stops(deploy_promote::stop_text(&stop))),
    };
    if planned.is_empty() {
        return Ok(Preview::Nothing);
    }
    let files = planned.iter().map(|(path, _, _)| path.clone()).collect();
    let uuids = planned
        .iter()
        .filter_map(|(_, _, uuid)| uuid.clone())
        .collect();
    let target = settings.target.clone().unwrap_or_default();
    let workspace = Workspace::open(
        Arc::new(Overlay::new(
            planned.into_iter().map(|(path, bytes, _)| (path, bytes)),
        )),
        opentide_workspace::Options { roots: options },
    )
    .map_err(|error| error.to_string())?;
    Ok(Preview::Promoted {
        workspace: Box::new(workspace),
        files,
        uuids,
        target,
    })
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

    fn github(reference: &str, extra: &[(&str, &str)]) -> Env {
        let mut pairs = vec![
            ("GITHUB_ACTIONS".to_owned(), "true".to_owned()),
            ("GITHUB_EVENT_NAME".to_owned(), "push".to_owned()),
            ("GITHUB_REF".to_owned(), reference.to_owned()),
            (
                opentide_compile::git::DEFAULT_BRANCH_ENV.to_owned(),
                "main".to_owned(),
            ),
        ];
        pairs.extend(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        Env::from_pairs(pairs)
    }

    #[test]
    fn only_a_release_push_to_the_default_branch_that_reads_its_changes_promotes() {
        let push = github("refs/heads/main", &[]);
        let feature = github("refs/heads/feature/foo", &[]);
        let tag = github("refs/tags/v1", &[]);
        let request = github("refs/heads/main", &[("GITHUB_EVENT_NAME", "pull_request")]);
        let local = Env::from_pairs(Vec::<(String, String)>::new());
        let release = [StatusStrategy::Release];
        assert!(applies(&release, true, &push));
        assert!(!applies(&release, false, &push));
        assert!(!applies(&[StatusStrategy::Preview], true, &push));
        assert!(!applies(&release, true, &feature));
        assert!(!applies(&release, true, &tag));
        assert!(!applies(&release, true, &request));
        assert!(!applies(&release, true, &local));
        // A known other branch is no warning; only an unknown default is.
        assert_eq!(undetermined_warning(&release, true, &feature, true), None);
        assert_eq!(undetermined_warning(&release, true, &push, true), None);
    }

    #[test]
    fn an_unknown_default_branch_skips_the_promotion_with_a_warning() {
        let release = [StatusStrategy::Release];
        let azure = Env::from_pairs([
            ("TF_BUILD".to_owned(), "True".to_owned()),
            ("BUILD_REASON".to_owned(), "IndividualCI".to_owned()),
            (
                "BUILD_SOURCEBRANCH".to_owned(),
                "refs/heads/main".to_owned(),
            ),
        ]);
        assert!(!applies(&release, true, &azure));
        let warning = undetermined_warning(&release, true, &azure, true).unwrap();
        assert!(warning.contains("OPENTIDE_DEFAULT_BRANCH"), "{warning}");
        assert!(warning.contains("default branch could not"), "{warning}");
        // Promotion off: nothing is said.
        assert_eq!(undetermined_warning(&release, true, &azure, false), None);
        // The pushed ref unknown is worded as such.
        let bare = Env::from_pairs([
            ("TF_BUILD".to_owned(), "True".to_owned()),
            ("BUILD_REASON".to_owned(), "IndividualCI".to_owned()),
        ]);
        let warning = undetermined_warning(&release, true, &bare, true).unwrap();
        assert!(warning.contains("branch this push is to"), "{warning}");
        // Not a promoting run: nothing to warn about.
        assert_eq!(undetermined_warning(&release, false, &azure, true), None);
        assert_eq!(
            undetermined_warning(&[StatusStrategy::Preview], true, &azure, true),
            None
        );
    }
}
